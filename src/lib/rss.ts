export type FeedItem = {
  title: string;
  link: string;
  guid: string;
  pubDate: Date | null;
  description: string;
};

export function escapeXml(value: string): string {
  return (
    value
      // Characters XML 1.0 forbids outright; upstream text could contain them.
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&apos;")
  );
}

export function buildRss({
  title,
  link,
  selfLink,
  description,
  items,
}: {
  title: string;
  link: string;
  selfLink: string;
  description: string;
  items: FeedItem[];
}): string {
  const entries = items
    .map(
      (item) => `    <item>
      <title>${escapeXml(item.title)}</title>
      <link>${escapeXml(item.link)}</link>
      <guid isPermaLink="false">${escapeXml(item.guid)}</guid>${
        item.pubDate ? `\n      <pubDate>${item.pubDate.toUTCString()}</pubDate>` : ""
      }
      <description>${escapeXml(item.description)}</description>
    </item>`,
    )
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(title)}</title>
    <link>${escapeXml(link)}</link>
    <atom:link href="${escapeXml(selfLink)}" rel="self" type="application/rss+xml"/>
    <description>${escapeXml(description)}</description>
${entries}
  </channel>
</rss>
`;
}
