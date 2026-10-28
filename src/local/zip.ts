import type { FileHandle } from "node:fs/promises";
import { open } from "node:fs/promises";
import { inflateRawSync } from "node:zlib";

// A minimal reader for OSV's archives: stored or deflated entries, with ZIP64
// for archives of more than 65,535 files. Small enough to read in full, so
// there's no third-party unzip code running on users' machines.

const EOCD = 0x06054b50;
const EOCD64_LOCATOR = 0x07064b50;
const EOCD64 = 0x06064b50;
const CENTRAL_HEADER = 0x02014b50;
const LOCAL_HEADER = 0x04034b50;
const MAX_U16 = 0xffff;
const MAX_U32 = 0xffffffff;
const MAX_COMMENT = 65_535;

export type ZipEntry = { name: string; data: Buffer };

type CentralEntry = {
  name: string;
  method: number;
  encrypted: boolean;
  compressedSize: number;
  size: number;
  localOffset: number;
};

// Yields each file's contents. Entries larger than maxEntryBytes, encrypted or
// with an unknown compression method are yielded as null data, so the caller
// can count them as skipped.
export async function* readZip(
  file: string,
  { maxEntryBytes }: { maxEntryBytes: number },
): AsyncGenerator<{ name: string; data: Buffer | null }> {
  const handle = await open(file, "r");
  try {
    const entries = await readCentralDirectory(handle);
    for (const entry of entries) {
      if (entry.name.endsWith("/")) continue;
      if (entry.encrypted || entry.size > maxEntryBytes || entry.compressedSize > maxEntryBytes) {
        yield { name: entry.name, data: null };
        continue;
      }
      yield { name: entry.name, data: await readEntry(handle, entry, maxEntryBytes) };
    }
  } finally {
    await handle.close();
  }
}

async function read(handle: FileHandle, position: number, length: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  if (bytesRead !== length) throw new Error("zip: unexpected end of file");
  return buffer;
}

async function readCentralDirectory(handle: FileHandle): Promise<CentralEntry[]> {
  const { size: fileSize } = await handle.stat();
  const tailLength = Math.min(fileSize, 22 + MAX_COMMENT);
  const tail = await read(handle, fileSize - tailLength, tailLength);

  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("zip: end of central directory not found");

  let count = tail.readUInt16LE(eocd + 10);
  let cdSize = tail.readUInt32LE(eocd + 12);
  let cdOffset = tail.readUInt32LE(eocd + 16);

  if (count === MAX_U16 || cdSize === MAX_U32 || cdOffset === MAX_U32) {
    const locatorAt = fileSize - tailLength + eocd - 20;
    const locator = await read(handle, locatorAt, 20);
    if (locator.readUInt32LE(0) !== EOCD64_LOCATOR) throw new Error("zip: ZIP64 locator not found");
    const eocd64 = await read(handle, Number(locator.readBigUInt64LE(8)), 56);
    if (eocd64.readUInt32LE(0) !== EOCD64) throw new Error("zip: ZIP64 end of central directory not found");
    count = Number(eocd64.readBigUInt64LE(32));
    cdSize = Number(eocd64.readBigUInt64LE(40));
    cdOffset = Number(eocd64.readBigUInt64LE(48));
  }
  if (cdOffset + cdSize > fileSize) throw new Error("zip: central directory out of range");

  const cd = await read(handle, cdOffset, cdSize);
  const entries: CentralEntry[] = [];
  let at = 0;
  for (let i = 0; i < count; i++) {
    if (cd.readUInt32LE(at) !== CENTRAL_HEADER) throw new Error("zip: bad central directory entry");
    const flags = cd.readUInt16LE(at + 8);
    const method = cd.readUInt16LE(at + 10);
    let compressedSize = cd.readUInt32LE(at + 20);
    let size = cd.readUInt32LE(at + 24);
    const nameLength = cd.readUInt16LE(at + 28);
    const extraLength = cd.readUInt16LE(at + 30);
    const commentLength = cd.readUInt16LE(at + 32);
    let localOffset = cd.readUInt32LE(at + 42);
    const name = cd.toString("utf8", at + 46, at + 46 + nameLength);

    // ZIP64 extra field: only the values that overflowed are present, in this order.
    let extra = at + 46 + nameLength;
    const extraEnd = extra + extraLength;
    while (extra + 4 <= extraEnd) {
      const id = cd.readUInt16LE(extra);
      const length = cd.readUInt16LE(extra + 2);
      if (id === 0x0001) {
        let field = extra + 4;
        if (size === MAX_U32) {
          size = Number(cd.readBigUInt64LE(field));
          field += 8;
        }
        if (compressedSize === MAX_U32) {
          compressedSize = Number(cd.readBigUInt64LE(field));
          field += 8;
        }
        if (localOffset === MAX_U32) localOffset = Number(cd.readBigUInt64LE(field));
      }
      extra += 4 + length;
    }

    entries.push({ name, method, encrypted: (flags & 1) === 1, compressedSize, size, localOffset });
    at = extraEnd + commentLength;
  }
  return entries;
}

async function readEntry(handle: FileHandle, entry: CentralEntry, maxEntryBytes: number): Promise<Buffer | null> {
  const header = await read(handle, entry.localOffset, 30);
  if (header.readUInt32LE(0) !== LOCAL_HEADER) throw new Error("zip: bad local header");
  const dataAt = entry.localOffset + 30 + header.readUInt16LE(26) + header.readUInt16LE(28);
  const compressed = await read(handle, dataAt, entry.compressedSize);
  if (entry.method === 0) return compressed;
  if (entry.method !== 8) return null;
  // The size cap holds even if the declared size lies.
  try {
    return inflateRawSync(compressed, { maxOutputLength: maxEntryBytes });
  } catch {
    return null;
  }
}
