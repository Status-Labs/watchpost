// Package names as the registries compare them, so "Django" matches "django"
// and "zope.interface" matches "zope-interface". Exact everywhere else.
export function normalizeName(ecosystem: string, name: string): string {
  switch (ecosystem) {
    case "PyPI":
      // PEP 503.
      return name.toLowerCase().replace(/[-_.]+/g, "-");
    case "crates.io":
      return name.toLowerCase().replace(/_/g, "-");
    case "NuGet":
    case "Packagist":
    case "Hackage":
      return name.toLowerCase();
    default:
      return name;
  }
}

// OSV's ecosystem field can carry a suffix, like "Debian:12".
export function baseEcosystem(ecosystem: string): string {
  return ecosystem.split(":")[0];
}
