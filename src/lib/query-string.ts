// Builds the shortest query string for a set of form values: empty values and
// values equal to the defaults are left out, so shared links stay short.
// Commas are valid in a query string; keeping them makes "critical,high" readable.
export function toQueryString(params: URLSearchParams | Record<string, string>, defaults: Record<string, string> = {}): string {
  const query = new URLSearchParams();
  for (const [name, value] of params instanceof URLSearchParams ? params : Object.entries(params)) {
    const text = value.trim();
    if (text && text !== defaults[name]) query.set(name, text);
  }
  const text = query.toString().replaceAll("%2C", ",");
  return text ? `?${text}` : "";
}
