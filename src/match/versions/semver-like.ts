// Ported from google/osv-scalibr semantic/version-semver-like.go (Apache-2.0) at commit 733765f.

import { isAsciiDigit } from "./utilities";

// Like a Semver 2.0.0 version, but with any number of numeric components and
// an optional leading "v".
export type SemverLikeVersion = {
  components: bigint[];
  build: string;
};

// With maxComponents of -1 the components are unlimited. Otherwise components
// past the limit move to the end of the build string as ".N".
export function parseSemverLikeVersion(str: string, maxComponents: number): SemverLikeVersion {
  const { components, build } = parseSemverLike(str);

  if (maxComponents === -1 || components.length <= maxComponents) {
    return { components, build };
  }

  const extra = components.slice(maxComponents).map((component) => `.${component}`);
  return { components: components.slice(0, maxComponents), build: build + extra.join("") };
}

function parseSemverLike(str: string): SemverLikeVersion {
  const components: bigint[] = [];
  let current = "";
  let foundBuild = false;

  const line = str.startsWith("v") ? str.slice(1) : str;

  for (const char of line) {
    if (foundBuild || isAsciiDigit(char)) {
      current += char;
      continue;
    }

    // Anything else ends the current component, and is either a "." before the
    // next one or the start of the build string.
    if (current !== "") {
      components.push(BigInt(current));
      current = "";
    }

    if (char === ".") continue;

    foundBuild = true;
    current = char;
  }

  if (!foundBuild && current !== "") {
    components.push(BigInt(current));
    current = "";
  }

  return { components, build: current };
}
