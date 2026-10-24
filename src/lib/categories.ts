// Categories for filtering: databases, infrastructure tools and so on. Upstream
// data has no categories, so these are matched by name: package names for OSV
// advisories, and vendor and product for CISA KEV entries. They're a best
// guess, and the rules can change without re-syncing anything.
//
// A keyword matches a whole segment of a name, split on anything that isn't a
// letter or digit: "redis" matches "redis-py" and "github.com/redis/go-redis",
// but not "ioredis" (which has its own keyword).

export type Category = {
  label: string;
  keywords: string[];
  // Every advisory in these ecosystems belongs to the category.
  ecosystems?: string[];
};

export const CATEGORIES = {
  databases: {
    label: "Databases",
    keywords: [
      "database", "databases", "sql", "mysql", "mysql2", "mysqlclient", "pymysql", "mariadb", "postgres", "postgresql",
      "pg", "pgx", "pq", "psycopg", "psycopg2", "asyncpg", "npgsql", "sqlite", "sqlite3", "rusqlite", "mongodb",
      "mongo", "mongoose", "pymongo", "mongoid", "redis", "ioredis", "predis", "jedis", "lettuce", "memcached",
      "cassandra", "elasticsearch", "opensearch", "clickhouse", "duckdb", "influxdb", "couchdb", "neo4j", "db2",
      "sqlalchemy", "sequelize", "typeorm", "prisma", "knex", "drizzle", "gorm", "sqlx", "diesel", "hibernate",
      "mybatis", "doctrine", "activerecord", "dapper", "entityframeworkcore", "h2database", "cockroachdb", "tidb",
      "vitess", "etcd", "chromadb", "qdrant", "weaviate", "pinecone", "milvus", "lancedb",
    ],
  },
  web: {
    label: "Web frameworks & servers",
    keywords: [
      "express", "next", "react", "vue", "nuxt", "angular", "svelte", "sveltekit", "remix", "astro", "koa", "fastify",
      "hapi", "nestjs", "django", "flask", "fastapi", "starlette", "tornado", "aiohttp", "werkzeug", "jinja2",
      "gin", "echo", "fiber", "gorilla", "actix", "axum", "rocket", "hyper", "warp", "spring", "springframework",
      "struts", "tomcat", "jetty", "undertow", "netty", "weblogic", "websphere", "jboss", "wildfly", "rails", "rack",
      "sinatra", "puma", "laravel", "symfony", "drupal", "wordpress", "joomla", "aspnetcore", "phoenix", "httpd",
      "nginx", "caddy", "iis", "liferay", "http", "coldfusion", "craft", "cms", "dotnetnuke", "dnn", "fusion middleware", "crushftp", "ofbiz", "vite", "webpack", "axios", "undici", "requests", "urllib3", "httpx",
      "guzzle",
    ],
  },
  infrastructure: {
    label: "Infrastructure & DevOps",
    keywords: [
      "kubernetes", "k8s", "docker", "moby", "containerd", "runc", "podman", "helm", "hashicorp", "terraform",
      "vault", "consul", "nomad", "ansible", "jenkins", "argo", "argoproj", "fluxcd", "prometheus", "grafana",
      "traefik", "istio", "envoy", "envoyproxy", "minio", "kafka", "rabbitmq", "nats", "activemq", "opentelemetry",
      "gitlab", "gitea", "bitbucket", "teamcity", "atlassian", "confluence", "jira", "vmware", "vcenter",
      "esxi", "openstack", "proxmox", "veeam", "solarwinds", "zabbix", "nagios", "pulumi", "boto3", "botocore",
      "awscli", "azure", "kubectl", "ingress", "log4j", "artifactory", "jfrog", "manageengine", "screenconnect", "connectwise", "simplehelp", "kaseya", "n-central", "omi",
    ],
    ecosystems: ["GitHub Actions"],
  },
  ai: {
    label: "AI & ML",
    keywords: [
      "tensorflow", "torch", "pytorch", "keras", "transformers", "diffusers", "huggingface", "langchain",
      "langgraph", "llama", "openai", "anthropic", "vllm", "ollama", "gradio", "streamlit", "mlflow", "ray",
      "jupyter", "jupyterlab", "notebook", "onnx", "scikit", "sklearn", "numpy", "pandas", "comfyui", "litellm",
      "bentoml", "mcp", "langflow",
    ],
  },
  auth: {
    label: "Auth & crypto",
    keywords: [
      "openssl", "boringssl", "libressl", "openssh", "ssh", "libssh", "paramiko", "jsonwebtoken", "jwt", "pyjwt",
      "jose", "passport", "oauth", "oauth2", "oidc", "openid", "saml", "ldap", "kerberos", "bcrypt", "argon2",
      "crypto", "cryptography", "pycryptodome", "rustls", "ring", "bouncycastle", "bcprov", "keycloak", "okta", "active directory",
      "authlib", "devise", "omniauth", "shiro", "pac4j", "nimbus", "forge", "tls", "x509", "sigstore",
    ],
  },
  os: {
    label: "Operating systems",
    keywords: [
      "windows", "win32k", "macos", "ios", "ipados", "watchos", "android", "linux", "kernel", "chromeos", "freebsd",
      "openbsd", "solaris", "aix", "ubuntu", "debian", "rhel", "glibc", "systemd", "sudo", "polkit", "apple", "firmware", "chipsets", "qualcomm", "mali", "gpu", "mobile devices",
    ],
  },
  network: {
    label: "Network & security devices",
    keywords: [
      "cisco", "fortinet", "fortios", "fortigate", "palo", "pan-os", "juniper", "junos", "citrix", "netscaler",
      "ivanti", "pulse", "f5", "big-ip", "sonicwall", "zyxel", "netgear", "d-link", "dlink", "tp-link", "mikrotik",
      "draytek", "sophos", "checkpoint", "barracuda", "ubiquiti", "watchguard", "arris", "qnap", "nas", "synology", "router", "firewall", "vpn",
    ],
  },
  browsers: {
    label: "Browsers",
    keywords: ["chrome", "chromium", "v8", "firefox", "mozilla", "safari", "webkit", "edge", "electron", "skia", "internet explorer"],
  },
  apps: {
    label: "Business & desktop apps",
    keywords: [
      "office", "word", "excel", "outlook", "exchange", "sharepoint", "zimbra", "roundcube", "webmail", "exim",
      "adobe", "acrobat", "flash", "sap", "netweaver", "e-business", "papercut", "accellion", "moveit", "winrar",
      "7-zip", "plex", "imagemagick", "java se", "jre", "silverlight", "whatsapp",
    ],
  },
} satisfies Record<string, Category>;

export type CategoryId = keyof typeof CATEGORIES;
export const CATEGORY_IDS = Object.keys(CATEGORIES) as CategoryId[];

export function isCategory(value: string): value is CategoryId {
  return Object.hasOwn(CATEGORIES, value);
}

const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");

// One case-insensitive pattern per category, valid in both JavaScript and
// Postgres (~*). A keyword must be a whole segment of the name.
export function categoryPattern(id: CategoryId): string {
  const words = CATEGORIES[id].keywords.map(escapeRegex).join("|");
  return `(^|[^a-z0-9])(${words})([^a-z0-9]|$)`;
}

export function categoryEcosystems(id: CategoryId): string[] {
  const category: Category = CATEGORIES[id];
  return category.ecosystems ?? [];
}

export function matchesCategory(id: CategoryId, { ecosystem, name }: { ecosystem?: string; name: string }): boolean {
  if (ecosystem && categoryEcosystems(id).includes(ecosystem)) return true;
  return new RegExp(categoryPattern(id), "i").test(name);
}
