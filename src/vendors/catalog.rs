// Copyright 2026 The CVECondor Authors
// SPDX-License-Identifier: Apache-2.0

//! The shipped vendor catalogue: for each popular service, the repo signals that
//! show a user depends on it and the feeds that announce its incidents. The
//! catalogue is wide on purpose; at runtime only detected (or hand-listed)
//! vendors are watched. Every feed URL here was fetched and parsed as RSS/Atom.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VendorFeedKind {
    Status,
    Security,
}

impl VendorFeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Security => "security",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorFeed {
    pub url: String,
    pub kind: VendorFeedKind,
}

/// Package names per OSV ecosystem; trailing `/*` for npm scopes, trailing `*` for prefixes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorPackages {
    #[serde(default)]
    pub npm: Vec<String>,
    #[serde(default, rename = "PyPI")]
    pub pypi: Vec<String>,
    #[serde(default, rename = "Go")]
    pub go: Vec<String>,
    #[serde(default, rename = "RubyGems")]
    pub rubygems: Vec<String>,
    #[serde(default, rename = "Packagist")]
    pub packagist: Vec<String>,
    #[serde(default, rename = "crates.io")]
    pub crates_io: Vec<String>,
}

impl VendorPackages {
    /// The names listed for an OSV ecosystem (`npm`, `PyPI`, `Go`, `RubyGems`, `Packagist`, `crates.io`).
    pub fn for_ecosystem(&self, ecosystem: &str) -> &[String] {
        match ecosystem {
            "npm" => &self.npm,
            "PyPI" => &self.pypi,
            "Go" => &self.go,
            "RubyGems" => &self.rubygems,
            "Packagist" => &self.packagist,
            "crates.io" => &self.crates_io,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorDef {
    pub id: String,
    pub name: String,
    /// Words an incident report uses for it (lowercase; matched as whole words).
    pub aliases: Vec<String>,
    /// Env var names: exact (`OPENAI_API_KEY`) or prefixes ending in `_` (`VERCEL_`).
    pub env: Vec<String>,
    /// Repo-relative path patterns: exact basenames, dirs with trailing `/`, or `**` globs.
    pub files: Vec<String>,
    pub packages: VendorPackages,
    /// Domain suffixes seen in config (`supabase.co`).
    pub hosts: Vec<String>,
    /// Container image repository prefixes (`cloudflare/cloudflared`, `ghcr.io/`).
    pub images: Vec<String>,
    /// GitHub deployment creator logins / environment-name patterns.
    pub deployers: Vec<String>,
    /// Verified RSS/Atom feeds only.
    pub feeds: Vec<VendorFeed>,
}

// ---- The table ------------------------------------------------------------------------------
// Written compactly: `Sig` holds the signals a vendor has (the rest default to none), and
// `vendor()` expands it into an owned `VendorDef`.

type Feed = (VendorFeedKind, &'static str);

const fn status(url: &'static str) -> Feed {
    (VendorFeedKind::Status, url)
}

const fn security(url: &'static str) -> Feed {
    (VendorFeedKind::Security, url)
}

/// `VendorPackages` as slices.
#[derive(Clone, Copy)]
struct Pk<'a> {
    npm: &'a [&'a str],
    pypi: &'a [&'a str],
    go: &'a [&'a str],
    rubygems: &'a [&'a str],
    packagist: &'a [&'a str],
    crates_io: &'a [&'a str],
}

const PK: Pk<'static> = Pk { npm: &[], pypi: &[], go: &[], rubygems: &[], packagist: &[], crates_io: &[] };

/// The signals of one vendor; everything absent is empty. An empty `aliases` means the
/// lowercased name (the TS default), so no vendor can have no aliases at all.
#[derive(Clone, Copy)]
struct Sig<'a> {
    aliases: &'a [&'a str],
    env: &'a [&'a str],
    files: &'a [&'a str],
    packages: Pk<'a>,
    hosts: &'a [&'a str],
    images: &'a [&'a str],
    deployers: &'a [&'a str],
    feeds: &'a [Feed],
}

const SIG: Sig<'static> = Sig { aliases: &[], env: &[], files: &[], packages: PK, hosts: &[], images: &[], deployers: &[], feeds: &[] };

fn owned(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

fn vendor(id: &str, name: &str, s: Sig) -> VendorDef {
    VendorDef {
        id: id.to_string(),
        name: name.to_string(),
        aliases: if s.aliases.is_empty() { vec![name.to_lowercase()] } else { owned(s.aliases) },
        env: owned(s.env),
        files: owned(s.files),
        packages: VendorPackages {
            npm: owned(s.packages.npm),
            pypi: owned(s.packages.pypi),
            go: owned(s.packages.go),
            rubygems: owned(s.packages.rubygems),
            packagist: owned(s.packages.packagist),
            crates_io: owned(s.packages.crates_io),
        },
        hosts: owned(s.hosts),
        images: owned(s.images),
        deployers: owned(s.deployers),
        feeds: s.feeds.iter().map(|(kind, url)| VendorFeed { url: (*url).to_string(), kind: *kind }).collect(),
    }
}

// Shared feeds (one vendor's incidents live on another's page).
const AWS_STATUS: Feed = status("https://status.aws.amazon.com/rss/all.rss");
const AWS_SECURITY: Feed = security("https://aws.amazon.com/security/security-bulletins/rss/feed/");
const GCP_STATUS: Feed = status("https://status.cloud.google.com/en/feed.atom");
const GCP_SECURITY: Feed = security("https://docs.cloud.google.com/feeds/google-cloud-security-bulletins.xml");
const MSRC: Feed = security("https://api.msrc.microsoft.com/update-guide/rss");
const TWILIO_STATUS: Feed = status("https://status.twilio.com/history.rss");
const PAYPAL_STATUS: Feed = status("https://www.paypal-status.com/feed/rss");
const CLOUDFLARE_STATUS: Feed = status("https://www.cloudflarestatus.com/history.rss");
const FIREBASE_STATUS: Feed = status("https://status.firebase.google.com/feed.atom");

// `..SIG` / `..PK` end every entry so a vendor can be extended without touching its tail, even
// where it already names every field.
#[allow(clippy::needless_update)]
pub static VENDORS: LazyLock<Vec<VendorDef>> = LazyLock::new(|| {
    vec![
        // Hosting / PaaS
        vendor(
            "vercel",
            "Vercel",
            Sig {
                env: &["VERCEL_"],
                files: &["vercel.json", ".vercel/"],
                packages: Pk { npm: &["@vercel/*", "vercel"], ..PK },
                hosts: &["vercel.app", "vercel.com"],
                deployers: &["vercel[bot]", "vercel"],
                feeds: &[status("https://www.vercel-status.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "netlify",
            "Netlify",
            Sig {
                env: &["NETLIFY_"],
                files: &["netlify.toml", ".netlify/"],
                packages: Pk { npm: &["@netlify/*", "netlify-cli"], ..PK },
                hosts: &["netlify.app", "netlify.com"],
                deployers: &["netlify[bot]"],
                feeds: &[status("https://www.netlifystatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "railway",
            "Railway",
            Sig {
                aliases: &["railway", "railway.app", "railway.com"],
                env: &["RAILWAY_"],
                files: &["railway.json", "railway.toml"],
                hosts: &["railway.app", "up.railway.app", "railway.internal"],
                deployers: &["railway-app[bot]"],
                // status.railway.com serves HTML only; its Instatus page serves the feed.
                feeds: &[status("https://railway.instatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "render",
            "Render",
            Sig {
                aliases: &["render.com"],
                env: &["RENDER_API_KEY", "RENDER_SERVICE_ID", "RENDER_EXTERNAL_URL", "RENDER_DEPLOY_HOOK_URL"],
                files: &["render.yaml"],
                hosts: &["onrender.com", "render.com"],
                feeds: &[status("https://status.render.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "flyio",
            "Fly.io",
            Sig {
                aliases: &["fly.io", "flyio"],
                env: &["FLY_API_TOKEN", "FLY_APP_NAME", "FLY_ACCESS_TOKEN", "FLY_REGION"],
                files: &["fly.toml"],
                hosts: &["fly.dev", "fly.io", "flycast"],
                images: &["flyio/"],
                feeds: &[status("https://status.flyio.net/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "heroku",
            "Heroku",
            Sig {
                env: &["HEROKU_"],
                files: &["Procfile", "app.json"],
                hosts: &["herokuapp.com", "herokudns.com"],
                feeds: &[status("https://status.heroku.com/feed")],
                ..SIG
            },
        ),
        vendor(
            "cloudflare",
            "Cloudflare",
            Sig {
                aliases: &["cloudflare", "cloudflare workers", "cloudflare pages", "cloudflare r2"],
                env: &["CLOUDFLARE_", "CF_API_TOKEN", "CF_API_KEY", "CF_ACCOUNT_ID", "CF_ZONE_ID"],
                files: &["wrangler.toml", "wrangler.json", "wrangler.jsonc", "wrangler.*.toml", "wrangler.*.json", "wrangler.*.jsonc", ".wrangler/"],
                packages: Pk { npm: &["@cloudflare/*", "wrangler"], pypi: &["cloudflare"], go: &["github.com/cloudflare/cloudflare-go*"], ..PK },
                hosts: &["workers.dev", "pages.dev", "r2.cloudflarestorage.com", "r2.dev"],
                images: &["cloudflare/"],
                deployers: &["cloudflare-workers-and-pages[bot]", "cloudflare-pages[bot]"],
                feeds: &[CLOUDFLARE_STATUS, security("https://blog.cloudflare.com/tag/security/rss/")],
                ..SIG
            },
        ),
        vendor(
            "digitalocean",
            "DigitalOcean",
            Sig {
                env: &["DIGITALOCEAN_"],
                files: &[".do/"],
                packages: Pk { go: &["github.com/digitalocean/godo"], pypi: &["python-digitalocean", "pydo"], ..PK },
                hosts: &["digitaloceanspaces.com", "ondigitalocean.app", "db.ondigitalocean.com"],
                feeds: &[status("https://status.digitalocean.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "hetzner",
            "Hetzner",
            Sig {
                aliases: &["hetzner"],
                env: &["HCLOUD_TOKEN", "HETZNER_"],
                packages: Pk { pypi: &["hcloud"], go: &["github.com/hetznercloud/hcloud-go*"], ..PK },
                hosts: &["your-objectstorage.com", "hetzner.cloud"],
                feeds: &[status("https://status.hetzner.com/en.atom")],
                ..SIG
            },
        ),
        vendor(
            "linode",
            "Linode (Akamai Cloud)",
            Sig {
                aliases: &["linode", "akamai cloud"],
                env: &["LINODE_"],
                packages: Pk { pypi: &["linode_api4"], go: &["github.com/linode/linodego"], ..PK },
                hosts: &["linodeobjects.com", "linode.com"],
                feeds: &[status("https://status.linode.com/history.rss")],
                ..SIG
            },
        ),
        vendor("vultr", "Vultr", Sig { env: &["VULTR_"], packages: Pk { go: &["github.com/vultr/govultr*"], ..PK }, hosts: &["vultrobjects.com"], ..SIG }),
        vendor(
            "ovhcloud",
            "OVHcloud",
            Sig {
                aliases: &["ovhcloud", "ovh"],
                env: &["OVH_"],
                packages: Pk { pypi: &["ovh"], npm: &["@ovhcloud/*", "ovh"], ..PK },
                hosts: &["ovh.net", "cloud.ovh.net"],
                feeds: &[status("https://public-cloud.status-ovhcloud.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "scaleway",
            "Scaleway",
            Sig {
                env: &["SCW_"],
                packages: Pk { pypi: &["scaleway"], go: &["github.com/scaleway/scaleway-sdk-go"], ..PK },
                hosts: &["scw.cloud"],
                feeds: &[status("https://status.scaleway.com/history.rss")],
                ..SIG
            },
        ),
        vendor("coolify", "Coolify", Sig { env: &["COOLIFY_"], images: &["ghcr.io/coollabsio/coolify", "coollabsio/coolify"], ..SIG }),
        vendor("dokploy", "Dokploy", Sig { env: &["DOKPLOY_"], images: &["dokploy/dokploy"], ..SIG }),
        vendor(
            "deno-deploy",
            "Deno Deploy",
            Sig {
                aliases: &["deno deploy"],
                env: &["DENO_DEPLOY_"],
                hosts: &["deno.dev", "deno.net"],
                deployers: &["deno-deploy[bot]"],
                feeds: &[status("https://denostatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "firebase",
            "Firebase",
            Sig {
                aliases: &["firebase", "firestore", "firebase hosting", "firebase auth"],
                env: &["FIREBASE_"],
                files: &["firebase.json", ".firebaserc", "firestore.rules"],
                packages: Pk {
                    npm: &["firebase", "firebase-admin", "firebase-tools", "@firebase/*"],
                    pypi: &["firebase-admin"],
                    go: &["firebase.google.com/go*"],
                    ..PK
                },
                hosts: &["firebaseapp.com", "firebaseio.com", "web.app"],
                feeds: &[FIREBASE_STATUS],
                ..SIG
            },
        ),
        vendor(
            "gitlab",
            "GitLab",
            Sig {
                env: &["GITLAB_", "CI_JOB_TOKEN"],
                files: &[".gitlab-ci.yml", ".gitlab/"],
                hosts: &["gitlab.com", "registry.gitlab.com"],
                images: &["registry.gitlab.com/", "gitlab/"],
                feeds: &[
                    status("https://status.gitlab.com/pages/5b36dc6502d06804c08349f7/rss"),
                    security("https://docs.gitlab.com/releases/patch-releases.xml"),
                ],
                ..SIG
            },
        ),
        // Big clouds
        vendor(
            "aws",
            "AWS",
            Sig {
                aliases: &["aws", "amazon web services"],
                env: &["AWS_"],
                files: &[
                    "serverless.yml",
                    "serverless.yaml",
                    "cdk.json",
                    "samconfig.toml",
                    "template.yaml",
                    "amplify/",
                    ".aws-sam/",
                    "buildspec.yml",
                    "appspec.yml",
                ],
                packages: Pk {
                    npm: &["aws-sdk", "@aws-sdk/*", "aws-cdk", "aws-cdk-lib", "@aws-amplify/*", "aws-amplify"],
                    pypi: &["boto3", "botocore", "aws-cdk-lib", "awscli"],
                    go: &["github.com/aws/aws-sdk-go*"],
                    rubygems: &["aws-sdk*"],
                    packagist: &["aws/aws-sdk-php"],
                    crates_io: &["aws-sdk-*", "aws-config"],
                    ..PK
                },
                hosts: &["amazonaws.com", "cloudfront.net", "awsapps.com"],
                images: &["public.ecr.aws/", "amazon/"],
                feeds: &[AWS_STATUS, AWS_SECURITY],
                ..SIG
            },
        ),
        vendor(
            "gcp",
            "Google Cloud",
            Sig {
                aliases: &["google cloud", "gcp", "google cloud platform"],
                env: &["GOOGLE_APPLICATION_CREDENTIALS", "GCP_", "GCLOUD_", "GOOGLE_CLOUD_PROJECT"],
                files: &["app.yaml", "cloudbuild.yaml", "cloudbuild.yml", ".gcloudignore"],
                packages: Pk {
                    npm: &["@google-cloud/*", "googleapis"],
                    pypi: &["google-cloud-*", "google-api-python-client"],
                    go: &["cloud.google.com/go*"],
                    rubygems: &["google-cloud-*"],
                    packagist: &["google/cloud-*"],
                    ..PK
                },
                hosts: &["googleapis.com", "run.app", "appspot.com", "cloudfunctions.net"],
                images: &["gcr.io/", "pkg.dev/"],
                feeds: &[GCP_STATUS, GCP_SECURITY],
                ..SIG
            },
        ),
        vendor(
            "azure",
            "Microsoft Azure",
            Sig {
                aliases: &["azure", "microsoft azure"],
                env: &["AZURE_"],
                files: &["azure.yaml", "host.json", "staticwebapp.config.json", "azure-pipelines.yml", ".azure/"],
                packages: Pk { npm: &["@azure/*"], pypi: &["azure-*"], go: &["github.com/Azure/azure-sdk-for-go*"], crates_io: &["azure_*"], ..PK },
                hosts: &["azurewebsites.net", "azure.com", "windows.net", "azurecr.io", "azurestaticapps.net"],
                images: &["mcr.microsoft.com/"],
                deployers: &["azure-static-web-apps[bot]"],
                feeds: &[status("https://azure.status.microsoft/en-us/status/feed/"), MSRC],
                ..SIG
            },
        ),
        vendor(
            "oracle-cloud",
            "Oracle Cloud",
            Sig {
                aliases: &["oracle cloud", "oci"],
                env: &["OCI_"],
                packages: Pk { pypi: &["oci"], npm: &["oci-sdk", "oci-common"], go: &["github.com/oracle/oci-go-sdk*"], ..PK },
                hosts: &["oraclecloud.com"],
                images: &["container-registry.oracle.com/"],
                feeds: &[
                    status("https://ocistatus.oraclecloud.com/api/v2/incident-summary.rss"),
                    security("https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml"),
                ],
                ..SIG
            },
        ),
        vendor(
            "ibm-cloud",
            "IBM Cloud",
            Sig {
                aliases: &["ibm cloud"],
                env: &["IBMCLOUD_", "IBM_CLOUD_"],
                packages: Pk { npm: &["ibm-cloud-sdk-core", "@ibm-cloud/*"], pypi: &["ibm-cloud-sdk-core", "ibm-*"], go: &["github.com/IBM/*"], ..PK },
                hosts: &["cloud.ibm.com", "appdomain.cloud"],
                images: &["icr.io/"],
                feeds: &[status("https://cloud.ibm.com/status/api/notifications/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "alibaba-cloud",
            "Alibaba Cloud",
            Sig {
                aliases: &["alibaba cloud", "aliyun"],
                env: &["ALIBABA_CLOUD_", "ALICLOUD_"],
                packages: Pk { npm: &["@alicloud/*"], pypi: &["alibabacloud-*", "aliyun-python-sdk-*"], ..PK },
                hosts: &["aliyuncs.com", "alibabacloud.com"],
                ..SIG
            },
        ),
        // Neoclouds / GPU and model hosting
        vendor(
            "modal",
            "Modal",
            Sig {
                aliases: &["modal labs", "modal.com"],
                env: &["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"],
                packages: Pk { pypi: &["modal"], ..PK },
                hosts: &["modal.run", "modal.com"],
                feeds: &[status("https://status.modal.com/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "replicate",
            "Replicate",
            Sig {
                env: &["REPLICATE_API_TOKEN"],
                packages: Pk { npm: &["replicate"], pypi: &["replicate"], ..PK },
                hosts: &["replicate.com", "replicate.delivery"],
                feeds: &[CLOUDFLARE_STATUS],
                ..SIG
            },
        ),
        vendor(
            "together",
            "Together AI",
            Sig {
                aliases: &["together ai", "together.ai"],
                env: &["TOGETHER_API_KEY"],
                packages: Pk { npm: &["together-ai"], pypi: &["together"], ..PK },
                hosts: &["together.xyz", "together.ai"],
                feeds: &[status("https://status.together.ai/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "fireworks",
            "Fireworks AI",
            Sig {
                aliases: &["fireworks ai", "fireworks.ai"],
                env: &["FIREWORKS_API_KEY"],
                packages: Pk { pypi: &["fireworks-ai"], npm: &["@fireworks-ai/*"], ..PK },
                hosts: &["fireworks.ai"],
                feeds: &[status("https://status.fireworks.ai/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "groq",
            "Groq",
            Sig {
                env: &["GROQ_API_KEY"],
                packages: Pk { npm: &["groq-sdk"], pypi: &["groq"], ..PK },
                hosts: &["groq.com"],
                feeds: &[status("https://groqstatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "baseten",
            "Baseten",
            Sig {
                env: &["BASETEN_API_KEY"],
                packages: Pk { pypi: &["truss", "baseten"], ..PK },
                hosts: &["baseten.co"],
                feeds: &[status("https://status.baseten.co/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "runpod",
            "RunPod",
            Sig {
                env: &["RUNPOD_API_KEY"],
                packages: Pk { pypi: &["runpod"], ..PK },
                hosts: &["runpod.io", "runpod.net"],
                images: &["runpod/"],
                feeds: &[status("https://uptime.runpod.io/feed")],
                ..SIG
            },
        ),
        vendor(
            "lambda",
            "Lambda",
            Sig {
                aliases: &["lambda labs", "lambda cloud", "lambda.ai"],
                env: &["LAMBDA_API_KEY"],
                hosts: &["lambdalabs.com", "lambda.ai"],
                feeds: &[status("https://status.lambda.ai/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "coreweave",
            "CoreWeave",
            Sig { env: &["COREWEAVE_"], hosts: &["coreweave.com"], feeds: &[status("https://status.coreweave.com/pages/5e126e998f2f032e1f8f0f4b/rss")], ..SIG },
        ),
        vendor(
            "crusoe",
            "Crusoe",
            Sig {
                aliases: &["crusoe", "crusoe cloud"],
                env: &["CRUSOE_"],
                hosts: &["crusoecloud.com"],
                feeds: &[status("https://status.crusoecloud.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "nebius",
            "Nebius",
            Sig {
                env: &["NEBIUS_"],
                packages: Pk { pypi: &["nebius"], ..PK },
                hosts: &["nebius.cloud", "nebius.com"],
                feeds: &[status("https://status.nebius.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "vastai",
            "Vast.ai",
            Sig { aliases: &["vast.ai", "vastai"], env: &["VAST_API_KEY"], packages: Pk { pypi: &["vastai"], ..PK }, hosts: &["vast.ai"], ..SIG },
        ),
        vendor(
            "paperspace",
            "Paperspace",
            Sig {
                env: &["PAPERSPACE_"],
                packages: Pk { pypi: &["gradient", "paperspace"], ..PK },
                hosts: &["paperspace.com"],
                feeds: &[status("https://status.paperspace.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "huggingface",
            "Hugging Face",
            Sig {
                aliases: &["hugging face", "huggingface"],
                env: &["HF_TOKEN", "HUGGINGFACE_", "HUGGING_FACE_HUB_TOKEN", "HF_API_TOKEN"],
                packages: Pk { pypi: &["huggingface-hub", "huggingface_hub", "transformers"], npm: &["@huggingface/*"], ..PK },
                hosts: &["huggingface.co", "hf.co", "hf.space"],
                feeds: &[status("https://status.huggingface.co/feed")],
                ..SIG
            },
        ),
        vendor(
            "cerebras",
            "Cerebras",
            Sig {
                env: &["CEREBRAS_API_KEY"],
                packages: Pk { pypi: &["cerebras-cloud-sdk"], npm: &["@cerebras/*"], ..PK },
                hosts: &["cerebras.ai"],
                feeds: &[status("https://status.cerebras.ai/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "sambanova",
            "SambaNova",
            Sig {
                env: &["SAMBANOVA_API_KEY"],
                packages: Pk { pypi: &["sambanova"], ..PK },
                hosts: &["sambanova.ai"],
                feeds: &[status("https://status.sambanova.ai/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "deepinfra",
            "DeepInfra",
            Sig {
                env: &["DEEPINFRA_API_KEY", "DEEPINFRA_TOKEN"],
                hosts: &["deepinfra.com"],
                feeds: &[status("https://status.deepinfra.com/status.atom")],
                ..SIG
            },
        ),
        // AI APIs
        vendor(
            "openai",
            "OpenAI",
            Sig {
                aliases: &["openai", "chatgpt"],
                env: &["OPENAI_API_KEY", "OPENAI_ORG_ID", "OPENAI_BASE_URL"],
                packages: Pk { npm: &["openai", "@openai/*"], pypi: &["openai"], go: &["github.com/openai/openai-go*"], ..PK },
                hosts: &["openai.com"],
                feeds: &[status("https://status.openai.com/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "anthropic",
            "Anthropic",
            Sig {
                aliases: &["anthropic", "claude"],
                env: &["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"],
                packages: Pk { npm: &["@anthropic-ai/*"], pypi: &["anthropic"], go: &["github.com/anthropics/anthropic-sdk-go"], ..PK },
                hosts: &["anthropic.com", "claude.ai"],
                feeds: &[status("https://status.claude.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "gemini",
            "Google Gemini",
            Sig {
                aliases: &["google gemini", "gemini api", "google ai studio", "vertex ai"],
                env: &["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENERATIVE_AI_API_KEY"],
                packages: Pk { npm: &["@google/genai", "@google/generative-ai"], pypi: &["google-genai", "google-generativeai"], ..PK },
                hosts: &["generativelanguage.googleapis.com", "aistudio.google.com"],
                feeds: &[GCP_STATUS],
                ..SIG
            },
        ),
        vendor(
            "openrouter",
            "OpenRouter",
            Sig { env: &["OPENROUTER_API_KEY"], packages: Pk { npm: &["@openrouter/*"], ..PK }, hosts: &["openrouter.ai"], ..SIG },
        ),
        vendor(
            "mistral",
            "Mistral AI",
            Sig {
                aliases: &["mistral", "mistral ai"],
                env: &["MISTRAL_API_KEY"],
                packages: Pk { npm: &["@mistralai/*"], pypi: &["mistralai"], ..PK },
                hosts: &["mistral.ai"],
                ..SIG
            },
        ),
        vendor(
            "cohere",
            "Cohere",
            Sig {
                env: &["COHERE_API_KEY", "CO_API_KEY"],
                packages: Pk { npm: &["cohere-ai"], pypi: &["cohere"], ..PK },
                hosts: &["cohere.com", "cohere.ai"],
                feeds: &[status("https://status.cohere.com/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "xai",
            "xAI",
            Sig {
                aliases: &["xai", "grok"],
                env: &["XAI_API_KEY"],
                packages: Pk { pypi: &["xai-sdk"], npm: &["@ai-sdk/xai"], ..PK },
                hosts: &["x.ai"],
                feeds: &[status("https://status.x.ai/feed.xml")],
                ..SIG
            },
        ),
        vendor(
            "deepseek",
            "DeepSeek",
            Sig {
                env: &["DEEPSEEK_API_KEY"],
                packages: Pk { npm: &["@ai-sdk/deepseek"], ..PK },
                hosts: &["deepseek.com"],
                feeds: &[status("https://status.deepseek.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "perplexity",
            "Perplexity",
            Sig {
                env: &["PERPLEXITY_API_KEY", "PPLX_API_KEY"],
                packages: Pk { pypi: &["perplexityai"], npm: &["@perplexity-ai/*"], ..PK },
                hosts: &["perplexity.ai"],
                feeds: &[status("https://status.perplexity.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "elevenlabs",
            "ElevenLabs",
            Sig {
                env: &["ELEVENLABS_API_KEY", "ELEVEN_API_KEY"],
                packages: Pk { npm: &["elevenlabs", "@elevenlabs/*"], pypi: &["elevenlabs"], ..PK },
                hosts: &["elevenlabs.io"],
                ..SIG
            },
        ),
        vendor(
            "deepgram",
            "Deepgram",
            Sig {
                env: &["DEEPGRAM_API_KEY"],
                packages: Pk { npm: &["@deepgram/*"], pypi: &["deepgram-sdk"], ..PK },
                hosts: &["deepgram.com"],
                feeds: &[status("https://status.deepgram.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "assemblyai",
            "AssemblyAI",
            Sig {
                env: &["ASSEMBLYAI_API_KEY"],
                packages: Pk { npm: &["assemblyai"], pypi: &["assemblyai"], ..PK },
                hosts: &["assemblyai.com"],
                feeds: &[status("https://status.assemblyai.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "tavily",
            "Tavily",
            Sig {
                env: &["TAVILY_API_KEY"],
                packages: Pk { npm: &["@tavily/*"], pypi: &["tavily-python"], ..PK },
                hosts: &["tavily.com"],
                feeds: &[status("https://status.tavily.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "exa",
            "Exa",
            Sig {
                aliases: &["exa.ai", "exa search"],
                env: &["EXA_API_KEY"],
                packages: Pk { npm: &["exa-js"], pypi: &["exa-py"], ..PK },
                hosts: &["exa.ai"],
                ..SIG
            },
        ),
        vendor(
            "firecrawl",
            "Firecrawl",
            Sig {
                env: &["FIRECRAWL_API_KEY"],
                packages: Pk { npm: &["@mendable/firecrawl-js"], pypi: &["firecrawl-py", "firecrawl"], ..PK },
                hosts: &["firecrawl.dev"],
                feeds: &[status("https://status.firecrawl.dev/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "serpapi",
            "SerpApi",
            Sig {
                env: &["SERPAPI_API_KEY", "SERPAPI_KEY"],
                packages: Pk { npm: &["serpapi"], pypi: &["google-search-results", "serpapi"], ..PK },
                hosts: &["serpapi.com"],
                feeds: &[status("https://status.serpapi.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "dataforseo",
            "DataForSEO",
            Sig { env: &["DATAFORSEO_"], packages: Pk { pypi: &["dataforseo-client"], ..PK }, hosts: &["dataforseo.com"], ..SIG },
        ),
        vendor(
            "langsmith",
            "LangSmith",
            Sig {
                aliases: &["langsmith"],
                env: &["LANGSMITH_", "LANGCHAIN_API_KEY"],
                packages: Pk { npm: &["langsmith"], pypi: &["langsmith"], ..PK },
                hosts: &["smith.langchain.com"],
                feeds: &[status("https://global.status.smith.langchain.com/gcp-us/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "langfuse",
            "Langfuse",
            Sig {
                env: &["LANGFUSE_"],
                packages: Pk { npm: &["langfuse", "@langfuse/*"], pypi: &["langfuse"], ..PK },
                hosts: &["langfuse.com"],
                feeds: &[status("https://status.langfuse.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "helicone",
            "Helicone",
            Sig {
                env: &["HELICONE_API_KEY"],
                packages: Pk { npm: &["@helicone/*"], pypi: &["helicone"], ..PK },
                hosts: &["helicone.ai"],
                feeds: &[status("https://status.helicone.ai/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "pinecone",
            "Pinecone",
            Sig {
                env: &["PINECONE_API_KEY", "PINECONE_ENVIRONMENT"],
                packages: Pk { npm: &["@pinecone-database/*"], pypi: &["pinecone", "pinecone-client"], ..PK },
                hosts: &["pinecone.io"],
                feeds: &[status("https://status.pinecone.io/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "weaviate",
            "Weaviate",
            Sig {
                env: &["WEAVIATE_"],
                packages: Pk { npm: &["weaviate-client", "weaviate-ts-client"], pypi: &["weaviate-client"], ..PK },
                hosts: &["weaviate.network", "weaviate.cloud"],
                images: &["semitechnologies/weaviate", "cr.weaviate.io/"],
                ..SIG
            },
        ),
        vendor(
            "qdrant",
            "Qdrant",
            Sig {
                env: &["QDRANT_"],
                packages: Pk { npm: &["@qdrant/*"], pypi: &["qdrant-client"], crates_io: &["qdrant-client"], ..PK },
                hosts: &["qdrant.io", "cloud.qdrant.io"],
                images: &["qdrant/qdrant"],
                feeds: &[status("https://status.qdrant.io/feed.rss")],
                ..SIG
            },
        ),
        // Databases / BaaS
        vendor(
            "supabase",
            "Supabase",
            Sig {
                env: &["SUPABASE_", "NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY"],
                files: &["supabase/config.toml", "supabase/"],
                packages: Pk { npm: &["@supabase/*"], pypi: &["supabase"], crates_io: &["supabase*"], ..PK },
                hosts: &["supabase.co", "supabase.com", "pooler.supabase.com"],
                images: &["supabase/"],
                feeds: &[status("https://status.supabase.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "neon",
            "Neon",
            Sig {
                aliases: &["neon", "neon.tech", "neon postgres"],
                env: &["NEON_API_KEY", "NEON_DATABASE_URL", "NEON_PROJECT_ID"],
                packages: Pk { npm: &["@neondatabase/*"], ..PK },
                hosts: &["neon.tech"],
                feeds: &[status("https://neonstatus.com/pages/6878fc85709daa75be6c7e3c/rss")],
                ..SIG
            },
        ),
        vendor(
            "planetscale",
            "PlanetScale",
            Sig {
                env: &["PLANETSCALE_"],
                packages: Pk { npm: &["@planetscale/*"], ..PK },
                hosts: &["psdb.cloud", "planetscale.com"],
                feeds: &[status("https://www.planetscalestatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "mongodb-atlas",
            "MongoDB Atlas",
            Sig {
                aliases: &["mongodb atlas", "mongodb"],
                env: &["MONGODB_URI", "MONGO_URI", "MONGODB_ATLAS_"],
                packages: Pk { npm: &["mongodb", "mongoose"], pypi: &["pymongo", "motor"], go: &["go.mongodb.org/mongo-driver*"], ..PK },
                hosts: &["mongodb.net"],
                feeds: &[status("https://status.mongodb.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "upstash",
            "Upstash",
            Sig {
                env: &["UPSTASH_"],
                packages: Pk { npm: &["@upstash/*"], pypi: &["upstash-redis", "upstash-*"], ..PK },
                hosts: &["upstash.io"],
                feeds: &[status("https://status.upstash.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "redis-cloud",
            "Redis Cloud",
            Sig {
                aliases: &["redis cloud", "redis enterprise cloud"],
                env: &["REDIS_CLOUD_"],
                hosts: &["redislabs.com", "redns.redis-cloud.com", "redis-cloud.com"],
                ..SIG
            },
        ),
        vendor(
            "turso",
            "Turso",
            Sig {
                env: &["TURSO_"],
                packages: Pk { npm: &["@libsql/*"], pypi: &["libsql-client", "libsql"], crates_io: &["libsql"], ..PK },
                hosts: &["turso.io", "turso.tech"],
                feeds: &[status("https://status.turso.tech/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "convex",
            "Convex",
            Sig {
                aliases: &["convex.dev"],
                env: &["CONVEX_", "NEXT_PUBLIC_CONVEX_URL"],
                files: &["convex.json", "convex/_generated/"],
                packages: Pk { npm: &["convex", "@convex-dev/*"], pypi: &["convex"], ..PK },
                hosts: &["convex.cloud", "convex.site"],
                feeds: &[status("https://status.convex.dev/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "xata",
            "Xata",
            Sig { env: &["XATA_"], files: &[".xatarc"], packages: Pk { npm: &["@xata.io/*"], pypi: &["xata"], ..PK }, hosts: &["xata.sh", "xata.tech"], ..SIG },
        ),
        vendor(
            "cockroachdb",
            "CockroachDB Cloud",
            Sig {
                aliases: &["cockroachdb", "cockroach labs"],
                env: &["COCKROACH_"],
                hosts: &["cockroachlabs.cloud"],
                images: &["cockroachdb/"],
                feeds: &[status("https://status.cockroachlabs.cloud/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "aiven",
            "Aiven",
            Sig {
                env: &["AIVEN_"],
                packages: Pk { pypi: &["aiven-client"], ..PK },
                hosts: &["aivencloud.com"],
                feeds: &[status("https://status.aiven.io/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "timescale",
            "Timescale (Tiger Data)",
            Sig {
                aliases: &["timescale", "timescaledb", "tiger data"],
                env: &["TIMESCALE_"],
                hosts: &["tsdb.cloud.timescale.com", "timescale.com"],
                images: &["timescale/"],
                feeds: &[status("https://status.tigerdata.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "clickhouse-cloud",
            "ClickHouse Cloud",
            Sig {
                aliases: &["clickhouse cloud", "clickhouse"],
                env: &["CLICKHOUSE_"],
                packages: Pk { npm: &["@clickhouse/*"], pypi: &["clickhouse-connect"], ..PK },
                hosts: &["clickhouse.cloud"],
                images: &["clickhouse/"],
                feeds: &[status("https://status.clickhouse.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "appwrite",
            "Appwrite",
            Sig {
                env: &["APPWRITE_"],
                files: &["appwrite.json", "appwrite.config.json"],
                packages: Pk { npm: &["appwrite", "node-appwrite"], pypi: &["appwrite"], ..PK },
                hosts: &["appwrite.io", "appwrite.global"],
                images: &["appwrite/"],
                feeds: &[status("https://appwrite.online/feed.atom")],
                ..SIG
            },
        ),
        vendor(
            "pocketbase",
            "PocketBase",
            Sig {
                env: &["POCKETBASE_"],
                files: &["pb_migrations/", "pb_hooks/"],
                packages: Pk { npm: &["pocketbase"], go: &["github.com/pocketbase/pocketbase"], ..PK },
                ..SIG
            },
        ),
        // Auth
        vendor(
            "auth0",
            "Auth0",
            Sig { env: &["AUTH0_"], packages: Pk { npm: &["@auth0/*", "auth0"], pypi: &["auth0-python"], ..PK }, hosts: &["auth0.com"], ..SIG },
        ),
        vendor(
            "okta",
            "Okta",
            Sig { env: &["OKTA_"], packages: Pk { npm: &["@okta/*"], pypi: &["okta"], ..PK }, hosts: &["okta.com", "oktapreview.com"], ..SIG },
        ),
        vendor(
            "clerk",
            "Clerk",
            Sig {
                aliases: &["clerk", "clerk.com"],
                env: &["CLERK_", "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY"],
                packages: Pk { npm: &["@clerk/*"], pypi: &["clerk-backend-api"], ..PK },
                hosts: &["clerk.accounts.dev", "clerk.com"],
                feeds: &[status("https://status.clerk.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "workos",
            "WorkOS",
            Sig {
                env: &["WORKOS_"],
                packages: Pk { npm: &["@workos-inc/*"], pypi: &["workos"], ..PK },
                hosts: &["workos.com"],
                feeds: &[status("https://status.workos.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "stytch",
            "Stytch",
            Sig {
                env: &["STYTCH_"],
                packages: Pk { npm: &["stytch", "@stytch/*"], pypi: &["stytch"], ..PK },
                hosts: &["stytch.com"],
                feeds: &[status("https://status.stytch.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "descope",
            "Descope",
            Sig {
                env: &["DESCOPE_"],
                packages: Pk { npm: &["@descope/*"], pypi: &["descope"], ..PK },
                hosts: &["descope.com"],
                feeds: &[status("https://descopestatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "kinde",
            "Kinde",
            Sig {
                env: &["KINDE_"],
                packages: Pk { npm: &["@kinde-oss/*"], ..PK },
                hosts: &["kinde.com"],
                feeds: &[status("https://status.kinde.com/history.rss")],
                ..SIG
            },
        ),
        // Payments
        vendor(
            "stripe",
            "Stripe",
            Sig {
                env: &["STRIPE_"],
                packages: Pk {
                    npm: &["stripe", "@stripe/*"],
                    pypi: &["stripe"],
                    go: &["github.com/stripe/stripe-go*"],
                    rubygems: &["stripe"],
                    packagist: &["stripe/stripe-php"],
                    ..PK
                },
                hosts: &["stripe.com"],
                feeds: &[status("https://www.stripestatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "paddle",
            "Paddle",
            Sig {
                aliases: &["paddle", "paddle.com"],
                env: &["PADDLE_"],
                packages: Pk { npm: &["@paddle/*"], pypi: &["paddle-python-sdk"], ..PK },
                hosts: &["paddle.com"],
                feeds: &[status("https://paddlestatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "lemonsqueezy",
            "Lemon Squeezy",
            Sig {
                aliases: &["lemon squeezy", "lemonsqueezy"],
                env: &["LEMONSQUEEZY_", "LEMON_SQUEEZY_"],
                packages: Pk { npm: &["@lemonsqueezy/*"], ..PK },
                hosts: &["lemonsqueezy.com"],
                feeds: &[status("https://status.lemonsqueezy.com/rss")],
                ..SIG
            },
        ),
        vendor(
            "polar",
            "Polar",
            Sig {
                aliases: &["polar.sh"],
                env: &["POLAR_ACCESS_TOKEN", "POLAR_WEBHOOK_SECRET", "POLAR_ORGANIZATION_ID"],
                packages: Pk { npm: &["@polar-sh/*"], pypi: &["polar-sdk"], ..PK },
                hosts: &["polar.sh"],
                feeds: &[status("https://status.polar.sh/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "paypal",
            "PayPal",
            Sig {
                env: &["PAYPAL_"],
                packages: Pk { npm: &["@paypal/*"], pypi: &["paypalrestsdk", "paypal-server-sdk"], ..PK },
                hosts: &["paypal.com"],
                feeds: &[PAYPAL_STATUS],
                ..SIG
            },
        ),
        vendor(
            "braintree",
            "Braintree",
            Sig {
                env: &["BRAINTREE_"],
                packages: Pk {
                    npm: &["braintree", "braintree-web"],
                    pypi: &["braintree"],
                    rubygems: &["braintree"],
                    packagist: &["braintree/braintree_php"],
                    ..PK
                },
                hosts: &["braintreegateway.com", "braintreepayments.com"],
                feeds: &[PAYPAL_STATUS],
                ..SIG
            },
        ),
        vendor("adyen", "Adyen", Sig { env: &["ADYEN_"], packages: Pk { npm: &["@adyen/*"], pypi: &["adyen"], ..PK }, hosts: &["adyen.com"], ..SIG }),
        vendor(
            "mollie",
            "Mollie",
            Sig {
                env: &["MOLLIE_"],
                packages: Pk { npm: &["@mollie/*"], pypi: &["mollie-api-python"], packagist: &["mollie/*"], ..PK },
                hosts: &["mollie.com"],
                feeds: &[status("https://status.mollie.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "square",
            "Square",
            Sig {
                aliases: &["square payments", "squareup"],
                env: &["SQUARE_ACCESS_TOKEN", "SQUARE_APPLICATION_ID", "SQUARE_LOCATION_ID", "SQUARE_ENVIRONMENT"],
                packages: Pk { npm: &["square"], pypi: &["squareup"], ..PK },
                hosts: &["squareup.com", "squareupsandbox.com"],
                ..SIG
            },
        ),
        vendor(
            "revenuecat",
            "RevenueCat",
            Sig {
                env: &["REVENUECAT_"],
                packages: Pk { npm: &["react-native-purchases", "@revenuecat/*"], ..PK },
                hosts: &["revenuecat.com"],
                feeds: &[status("https://status.revenuecat.com/history.rss")],
                ..SIG
            },
        ),
        // Email / SMS / messaging
        vendor(
            "resend",
            "Resend",
            Sig {
                env: &["RESEND_API_KEY"],
                packages: Pk { npm: &["resend"], pypi: &["resend"], ..PK },
                hosts: &["resend.com", "resend.dev"],
                feeds: &[status("https://resend-status.com/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "sendgrid",
            "SendGrid",
            Sig {
                env: &["SENDGRID_API_KEY"],
                packages: Pk { npm: &["@sendgrid/*"], pypi: &["sendgrid"], ..PK },
                hosts: &["sendgrid.net", "sendgrid.com"],
                feeds: &[TWILIO_STATUS],
                ..SIG
            },
        ),
        vendor(
            "twilio",
            "Twilio",
            Sig {
                env: &["TWILIO_"],
                packages: Pk { npm: &["twilio"], pypi: &["twilio"], rubygems: &["twilio-ruby"], packagist: &["twilio/sdk"], ..PK },
                hosts: &["twilio.com"],
                feeds: &[TWILIO_STATUS],
                ..SIG
            },
        ),
        vendor(
            "postmark",
            "Postmark",
            Sig { env: &["POSTMARK_"], packages: Pk { npm: &["postmark"], pypi: &["postmarker"], ..PK }, hosts: &["postmarkapp.com"], ..SIG },
        ),
        vendor(
            "mailgun",
            "Mailgun",
            Sig {
                env: &["MAILGUN_"],
                packages: Pk { npm: &["mailgun.js", "mailgun-js"], ..PK },
                hosts: &["mailgun.net", "mailgun.org"],
                feeds: &[status("https://status.mailgun.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "amazon-ses",
            "Amazon SES",
            Sig {
                aliases: &["amazon ses", "aws ses", "simple email service"],
                env: &["SES_", "AWS_SES_"],
                packages: Pk { npm: &["@aws-sdk/client-ses", "@aws-sdk/client-sesv2"], ..PK },
                hosts: &["email-smtp.us-east-1.amazonaws.com", "amazonses.com"],
                feeds: &[AWS_STATUS],
                ..SIG
            },
        ),
        vendor(
            "brevo",
            "Brevo",
            Sig {
                aliases: &["brevo", "sendinblue"],
                env: &["BREVO_", "SENDINBLUE_"],
                packages: Pk { npm: &["@getbrevo/*", "sib-api-v3-sdk"], pypi: &["brevo-python", "sib-api-v3-sdk"], ..PK },
                hosts: &["brevo.com", "sendinblue.com"],
                feeds: &[status("https://status.brevo.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "mailchimp",
            "Mailchimp",
            Sig {
                aliases: &["mailchimp", "mandrill"],
                env: &["MAILCHIMP_", "MANDRILL_"],
                packages: Pk { npm: &["@mailchimp/*"], pypi: &["mailchimp3", "mailchimp-marketing"], ..PK },
                hosts: &["mailchimp.com", "mandrillapp.com", "list-manage.com"],
                ..SIG
            },
        ),
        vendor(
            "loops",
            "Loops",
            Sig {
                aliases: &["loops.so"],
                env: &["LOOPS_API_KEY"],
                packages: Pk { npm: &["loops"], pypi: &["loops-so"], ..PK },
                hosts: &["loops.so"],
                feeds: &[status("https://status.loops.so/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "pusher",
            "Pusher",
            Sig {
                env: &["PUSHER_"],
                packages: Pk { npm: &["pusher", "pusher-js"], pypi: &["pusher"], packagist: &["pusher/pusher-php-server"], ..PK },
                hosts: &["pusher.com", "pusherapp.com"],
                feeds: &[status("https://status.pusher.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "ably",
            "Ably",
            Sig {
                env: &["ABLY_"],
                packages: Pk { npm: &["ably"], pypi: &["ably"], ..PK },
                hosts: &["ably.io", "ably.com"],
                feeds: &[status("https://status.ably.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "knock",
            "Knock",
            Sig {
                aliases: &["knock.app"],
                env: &["KNOCK_API_KEY", "KNOCK_SECRET_API_KEY", "NEXT_PUBLIC_KNOCK_PUBLIC_API_KEY"],
                packages: Pk { npm: &["@knocklabs/*"], pypi: &["knockapi"], ..PK },
                hosts: &["knock.app"],
                feeds: &[status("https://status.knock.app/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "novu",
            "Novu",
            Sig { env: &["NOVU_"], packages: Pk { npm: &["@novu/*"], pypi: &["novu"], ..PK }, hosts: &["novu.co"], images: &["ghcr.io/novuhq/"], ..SIG },
        ),
        vendor(
            "slack",
            "Slack",
            Sig {
                env: &["SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL", "SLACK_SIGNING_SECRET", "SLACK_APP_TOKEN"],
                packages: Pk { npm: &["@slack/*"], pypi: &["slack-sdk", "slack-bolt"], ..PK },
                hosts: &["hooks.slack.com", "slack.com"],
                feeds: &[status("https://slack-status.com/feed/rss")],
                ..SIG
            },
        ),
        vendor(
            "discord",
            "Discord",
            Sig {
                env: &["DISCORD_"],
                packages: Pk { npm: &["discord.js", "@discordjs/*"], pypi: &["discord.py", "discord"], ..PK },
                hosts: &["discord.com", "discordapp.com"],
                feeds: &[status("https://discordstatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "telegram",
            "Telegram",
            Sig {
                aliases: &["telegram", "telegram bot api"],
                env: &["TELEGRAM_BOT_TOKEN", "TELEGRAM_"],
                packages: Pk { npm: &["telegraf", "grammy", "node-telegram-bot-api"], pypi: &["python-telegram-bot", "aiogram"], ..PK },
                hosts: &["api.telegram.org"],
                ..SIG
            },
        ),
        // Observability / analytics
        vendor(
            "sentry",
            "Sentry",
            Sig {
                env: &["SENTRY_", "NEXT_PUBLIC_SENTRY_DSN"],
                files: &["sentry.properties", ".sentryclirc", "sentry.client.config.ts", "sentry.server.config.ts"],
                packages: Pk {
                    npm: &["@sentry/*"],
                    pypi: &["sentry-sdk"],
                    go: &["github.com/getsentry/sentry-go"],
                    rubygems: &["sentry-ruby"],
                    crates_io: &["sentry"],
                    ..PK
                },
                hosts: &["sentry.io", "ingest.sentry.io"],
                feeds: &[status("https://status.sentry.io/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "datadog",
            "Datadog",
            Sig {
                env: &["DATADOG_", "DD_API_KEY", "DD_APP_KEY", "DD_SITE", "DD_ENV", "DD_SERVICE"],
                files: &["datadog.yaml"],
                packages: Pk { npm: &["dd-trace", "@datadog/*"], pypi: &["ddtrace", "datadog"], go: &["gopkg.in/DataDog/*", "github.com/DataDog/*"], ..PK },
                hosts: &["datadoghq.com", "datadoghq.eu"],
                images: &["datadog/", "gcr.io/datadoghq/"],
                feeds: &[status("https://status.datadoghq.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "newrelic",
            "New Relic",
            Sig {
                aliases: &["new relic", "newrelic"],
                env: &["NEW_RELIC_"],
                files: &["newrelic.js", "newrelic.yml", "newrelic.ini"],
                packages: Pk { npm: &["newrelic", "@newrelic/*"], pypi: &["newrelic"], go: &["github.com/newrelic/go-agent*"], ..PK },
                hosts: &["newrelic.com", "nr-data.net"],
                images: &["newrelic/"],
                feeds: &[status("https://status.newrelic.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "grafana-cloud",
            "Grafana Cloud",
            Sig {
                aliases: &["grafana cloud", "grafana"],
                env: &["GRAFANA_"],
                hosts: &["grafana.net", "grafana.com"],
                images: &["grafana/"],
                feeds: &[status("https://status.grafana.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "honeycomb",
            "Honeycomb",
            Sig {
                aliases: &["honeycomb.io", "honeycomb"],
                env: &["HONEYCOMB_"],
                packages: Pk { npm: &["@honeycombio/*"], pypi: &["honeycomb-opentelemetry"], ..PK },
                hosts: &["honeycomb.io"],
                feeds: &[status("https://status.honeycomb.io/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "betterstack",
            "Better Stack",
            Sig {
                aliases: &["better stack", "betterstack", "logtail", "better uptime"],
                env: &["BETTERSTACK_", "BETTER_STACK_", "LOGTAIL_"],
                packages: Pk { npm: &["@logtail/*"], pypi: &["logtail-python"], ..PK },
                hosts: &["betterstack.com", "logtail.com", "betterstackdata.com"],
                feeds: &[status("https://status.betterstack.com/feed")],
                ..SIG
            },
        ),
        vendor(
            "posthog",
            "PostHog",
            Sig {
                env: &["POSTHOG_", "NEXT_PUBLIC_POSTHOG_KEY", "NEXT_PUBLIC_POSTHOG_HOST"],
                packages: Pk { npm: &["posthog-js", "posthog-node", "posthog-react-native"], pypi: &["posthog"], ..PK },
                hosts: &["posthog.com", "i.posthog.com"],
                feeds: &[status("https://www.posthogstatus.com/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "mixpanel",
            "Mixpanel",
            Sig {
                env: &["MIXPANEL_", "NEXT_PUBLIC_MIXPANEL_TOKEN"],
                packages: Pk { npm: &["mixpanel", "mixpanel-browser"], pypi: &["mixpanel"], ..PK },
                hosts: &["mixpanel.com"],
                feeds: &[status("https://www.mixpanelstatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "amplitude",
            "Amplitude",
            Sig {
                env: &["AMPLITUDE_", "NEXT_PUBLIC_AMPLITUDE_API_KEY"],
                packages: Pk { npm: &["@amplitude/*", "amplitude-js"], pypi: &["amplitude-analytics"], ..PK },
                hosts: &["amplitude.com"],
                feeds: &[status("https://status.amplitude.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "segment",
            "Segment",
            Sig {
                aliases: &["twilio segment", "segment.io", "segment.com"],
                env: &["SEGMENT_WRITE_KEY", "SEGMENT_"],
                packages: Pk { npm: &["@segment/*", "analytics-node"], pypi: &["segment-analytics-python", "analytics-python"], ..PK },
                hosts: &["segment.io", "segment.com", "segmentapis.com"],
                feeds: &[TWILIO_STATUS],
                ..SIG
            },
        ),
        vendor(
            "launchdarkly",
            "LaunchDarkly",
            Sig {
                env: &["LAUNCHDARKLY_", "LD_SDK_KEY", "LD_CLIENT_SIDE_ID"],
                packages: Pk {
                    npm: &["@launchdarkly/*", "launchdarkly-node-server-sdk", "launchdarkly-js-client-sdk"],
                    pypi: &["launchdarkly-server-sdk"],
                    ..PK
                },
                hosts: &["launchdarkly.com"],
                feeds: &[status("https://status.launchdarkly.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "statsig",
            "Statsig",
            Sig {
                env: &["STATSIG_"],
                packages: Pk { npm: &["statsig-node", "statsig-js", "@statsig/*"], pypi: &["statsig"], ..PK },
                hosts: &["statsig.com", "statsigapi.net"],
                feeds: &[status("https://status.statsig.com/history.rss")],
                ..SIG
            },
        ),
        // Storage / CDN / media / search
        vendor(
            "backblaze",
            "Backblaze B2",
            Sig {
                aliases: &["backblaze", "backblaze b2"],
                env: &["B2_APPLICATION_KEY", "B2_APPLICATION_KEY_ID", "B2_KEY_ID", "B2_BUCKET", "BACKBLAZE_"],
                packages: Pk { pypi: &["b2sdk", "b2"], ..PK },
                hosts: &["backblazeb2.com"],
                ..SIG
            },
        ),
        vendor(
            "wasabi",
            "Wasabi",
            Sig {
                aliases: &["wasabi", "wasabi cloud storage"],
                env: &["WASABI_"],
                hosts: &["wasabisys.com"],
                feeds: &[status("https://status.wasabi.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "uploadthing",
            "UploadThing",
            Sig {
                env: &["UPLOADTHING_"],
                packages: Pk { npm: &["uploadthing", "@uploadthing/*"], ..PK },
                hosts: &["utfs.io", "uploadthing.com", "ufs.sh"],
                ..SIG
            },
        ),
        vendor(
            "cloudinary",
            "Cloudinary",
            Sig {
                env: &["CLOUDINARY_", "NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME"],
                packages: Pk { npm: &["cloudinary", "next-cloudinary", "@cloudinary/*"], pypi: &["cloudinary"], ..PK },
                hosts: &["cloudinary.com", "res.cloudinary.com"],
                feeds: &[status("https://status.cloudinary.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "mux",
            "Mux",
            Sig {
                aliases: &["mux", "mux video", "mux.com"],
                env: &["MUX_TOKEN_ID", "MUX_TOKEN_SECRET", "MUX_"],
                packages: Pk { npm: &["@mux/*"], pypi: &["mux-python"], ..PK },
                hosts: &["mux.com", "mux.dev"],
                feeds: &[status("https://status.mux.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "imgix",
            "imgix",
            Sig {
                env: &["IMGIX_"],
                packages: Pk { npm: &["@imgix/*", "imgix-core-js"], pypi: &["imgix"], ..PK },
                hosts: &["imgix.net"],
                feeds: &[status("https://status.imgix.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "fastly",
            "Fastly",
            Sig {
                env: &["FASTLY_"],
                files: &["fastly.toml"],
                packages: Pk { npm: &["@fastly/*", "fastly"], pypi: &["fastly"], crates_io: &["fastly"], ..PK },
                hosts: &["fastly.net", "global.ssl.fastly.net", "edgecompute.app"],
                ..SIG
            },
        ),
        vendor(
            "bunny",
            "Bunny.net",
            Sig {
                aliases: &["bunny.net", "bunnycdn", "bunny cdn"],
                env: &["BUNNY_", "BUNNYCDN_"],
                packages: Pk { npm: &["@bunny.net/*"], ..PK },
                hosts: &["b-cdn.net", "bunnycdn.com", "bunny.net"],
                feeds: &[status("https://status.bunny.net/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "akamai",
            "Akamai",
            Sig {
                env: &["AKAMAI_"],
                files: &[".edgerc"],
                packages: Pk { npm: &["akamai-edgegrid"], pypi: &["edgegrid-python"], ..PK },
                hosts: &["akamaized.net", "akamaiedge.net", "edgekey.net", "edgesuite.net"],
                feeds: &[status("https://www.akamaistatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "algolia",
            "Algolia",
            Sig {
                env: &["ALGOLIA_", "NEXT_PUBLIC_ALGOLIA_APP_ID"],
                packages: Pk { npm: &["algoliasearch", "@algolia/*", "react-instantsearch"], pypi: &["algoliasearch"], ..PK },
                hosts: &["algolia.net", "algolianet.com", "algolia.io"],
                ..SIG
            },
        ),
        vendor(
            "meilisearch",
            "Meilisearch Cloud",
            Sig {
                aliases: &["meilisearch"],
                env: &["MEILI_", "MEILISEARCH_"],
                packages: Pk { npm: &["meilisearch"], pypi: &["meilisearch"], ..PK },
                hosts: &["meilisearch.io", "meilisearch.com"],
                images: &["getmeili/meilisearch"],
                feeds: &[status("https://status.meilisearch.com/en/feed.rss")],
                ..SIG
            },
        ),
        vendor(
            "typesense",
            "Typesense Cloud",
            Sig {
                aliases: &["typesense"],
                env: &["TYPESENSE_"],
                packages: Pk { npm: &["typesense"], pypi: &["typesense"], ..PK },
                hosts: &["typesense.net"],
                images: &["typesense/typesense"],
                ..SIG
            },
        ),
        // Dev platform / registries / CI / secrets
        vendor(
            "github",
            "GitHub",
            Sig {
                aliases: &["github", "github actions", "ghcr", "github pages"],
                env: &["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_APP_"],
                files: &[".github/", "CNAME"],
                packages: Pk { npm: &["@octokit/*"], pypi: &["pygithub"], ..PK },
                hosts: &["github.com", "githubusercontent.com", "github.io", "ghcr.io"],
                images: &["ghcr.io/"],
                deployers: &["github-pages", "github-actions[bot]"],
                feeds: &[status("https://www.githubstatus.com/history.rss"), security("https://github.blog/security/feed/")],
                ..SIG
            },
        ),
        vendor(
            "npm",
            "npm registry",
            Sig {
                aliases: &["npm registry", "npmjs"],
                env: &["NPM_TOKEN"],
                files: &["package-lock.json", ".npmrc"],
                hosts: &["registry.npmjs.org", "npmjs.com"],
                feeds: &[status("https://status.npmjs.org/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "pypi",
            "PyPI",
            Sig {
                aliases: &["pypi", "python package index"],
                env: &["PYPI_TOKEN", "PYPI_API_TOKEN", "TWINE_PASSWORD"],
                hosts: &["pypi.org", "files.pythonhosted.org"],
                feeds: &[status("https://status.python.org/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "dockerhub",
            "Docker Hub",
            Sig {
                aliases: &["docker hub", "dockerhub"],
                env: &["DOCKERHUB_", "DOCKER_HUB_"],
                hosts: &["docker.io", "hub.docker.com"],
                images: &["docker.io/"],
                feeds: &[status("https://www.dockerstatus.com/history.rss"), security("https://www.docker.com/blog/category/security/feed/")],
                ..SIG
            },
        ),
        vendor(
            "circleci",
            "CircleCI",
            Sig {
                env: &["CIRCLECI_", "CIRCLE_TOKEN"],
                files: &[".circleci/"],
                hosts: &["circleci.com"],
                images: &["cimg/", "circleci/"],
                feeds: &[status("https://status.circleci.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "travis",
            "Travis CI",
            Sig {
                aliases: &["travis ci", "travis-ci"],
                env: &["TRAVIS_"],
                files: &[".travis.yml"],
                hosts: &["travis-ci.com"],
                feeds: &[status("https://www.traviscistatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "buildkite",
            "Buildkite",
            Sig {
                env: &["BUILDKITE_"],
                files: &[".buildkite/"],
                hosts: &["buildkite.com"],
                images: &["buildkite/"],
                feeds: &[status("https://www.buildkitestatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "doppler",
            "Doppler",
            Sig {
                aliases: &["doppler", "doppler secrets"],
                env: &["DOPPLER_"],
                files: &["doppler.yaml"],
                hosts: &["doppler.com"],
                images: &["dopplerhq/"],
                feeds: &[status("https://www.dopplerstatus.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "infisical",
            "Infisical",
            Sig {
                env: &["INFISICAL_"],
                files: &[".infisical.json"],
                packages: Pk { npm: &["@infisical/*"], pypi: &["infisical-python", "infisicalsdk"], ..PK },
                hosts: &["infisical.com"],
                images: &["infisical/"],
                feeds: &[status("https://status.infisical.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "1password",
            "1Password",
            Sig {
                aliases: &["1password"],
                env: &["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "OP_CONNECT_HOST"],
                packages: Pk { npm: &["@1password/*"], pypi: &["onepassword-sdk"], ..PK },
                hosts: &["1password.com"],
                images: &["1password/"],
                feeds: &[status("https://status.1password.com/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "hashicorp",
            "HashiCorp Cloud",
            Sig {
                aliases: &["hashicorp", "hcp vault", "terraform cloud", "hcp terraform"],
                env: &["VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "HCP_CLIENT_ID", "HCP_CLIENT_SECRET", "TFE_TOKEN"],
                packages: Pk { npm: &["node-vault"], pypi: &["hvac"], go: &["github.com/hashicorp/vault/api"], ..PK },
                hosts: &["hashicorp.cloud", "app.terraform.io"],
                images: &["hashicorp/"],
                feeds: &[status("https://status.hashicorp.com/history.rss"), security("https://discuss.hashicorp.com/c/security/52.rss")],
                ..SIG
            },
        ),
        vendor(
            "expo",
            "Expo",
            Sig {
                aliases: &["expo", "expo eas", "eas build"],
                env: &["EXPO_"],
                files: &["eas.json"],
                packages: Pk { npm: &["expo", "@expo/*", "eas-cli"], ..PK },
                hosts: &["expo.dev", "expo.io"],
                feeds: &[status("https://status.expo.dev/history.rss")],
                ..SIG
            },
        ),
        vendor(
            "tailscale",
            "Tailscale",
            Sig {
                env: &["TS_AUTHKEY", "TS_OAUTH_CLIENT_ID", "TS_OAUTH_SECRET", "TAILSCALE_"],
                hosts: &["ts.net", "tailscale.com"],
                images: &["tailscale/"],
                feeds: &[status("https://status.tailscale.com/history.rss"), security("https://tailscale.com/security-bulletins/index.xml")],
                ..SIG
            },
        ),
        vendor(
            "ngrok",
            "ngrok",
            Sig {
                env: &["NGROK_"],
                files: &["ngrok.yml"],
                packages: Pk { npm: &["ngrok", "@ngrok/*"], pypi: &["ngrok", "pyngrok"], ..PK },
                hosts: &["ngrok.io", "ngrok.app", "ngrok-free.app"],
                images: &["ngrok/"],
                feeds: &[status("https://status.ngrok.com/history.rss")],
                ..SIG
            },
        ),
        // Accounts used outside code: no repo signals, listed by id in config.
        vendor(
            "google-workspace",
            "Google Workspace",
            Sig {
                aliases: &["google workspace", "gmail", "google drive"],
                feeds: &[status("https://www.google.com/appsstatus/dashboard/en/feed.atom")],
                ..SIG
            },
        ),
        vendor(
            "microsoft-365",
            "Microsoft 365",
            Sig {
                aliases: &["microsoft 365", "office 365", "outlook", "microsoft teams"],
                feeds: &[status("https://status.cloud.microsoft/api/feed/mac"), MSRC],
                ..SIG
            },
        ),
        vendor("notion", "Notion", Sig { feeds: &[status("https://www.notion-status.com/history.rss")], ..SIG }),
        vendor("linear", "Linear", Sig { aliases: &["linear.app"], feeds: &[status("https://linearstatus.com/history.rss")], ..SIG }),
        vendor(
            "atlassian",
            "Atlassian (Jira)",
            Sig { aliases: &["atlassian", "jira", "confluence"], feeds: &[status("https://jira-software.status.atlassian.com/history.rss")], ..SIG },
        ),
        vendor("figma", "Figma", Sig { feeds: &[status("https://status.figma.com/history.rss")], ..SIG }),
        vendor("lastpass", "LastPass", Sig { feeds: &[status("https://status.lastpass.com/history.rss")], ..SIG }),
        vendor("bitwarden", "Bitwarden", Sig { feeds: &[status("https://status.bitwarden.com/state_feed/feed")], ..SIG }),
        vendor("namecheap", "Namecheap", Sig { feeds: &[status("https://www.namecheap.com/status-updates/feed/")], ..SIG }),
        vendor("godaddy", "GoDaddy", Sig { ..SIG }),
        vendor("porkbun", "Porkbun", Sig { ..SIG }),
    ]
});

/// Whether a catalogue file pattern names `path`: `*` is one path segment's characters, `**` any
/// characters, a trailing `/` a directory anywhere, anything else a basename or full path.
/// The TS builds the regex `^(?:.*/)?<body>$`; this matcher is the same language without
/// compiling one per call (JS `.` stops at line terminators, `[^/]` does not).
fn file_matches(pattern: &str, path: &str) -> bool {
    let p = path.strip_prefix("./").unwrap_or(path);
    if pattern.contains('*') {
        return glob_matches(pattern, p);
    }
    if pattern.ends_with('/') {
        return p.starts_with(pattern) || p.contains(&format!("/{pattern}"));
    }
    p == pattern || p.strip_suffix(pattern).is_some_and(|rest| rest.ends_with('/'))
}

#[derive(Clone, Copy)]
enum Tok {
    Lit(char),
    /// `*`: `[^/]*`.
    Star,
    /// `**`: `.*`.
    Any,
}

fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let mut toks = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '*' {
            if chars.peek() == Some(&'*') {
                chars.next();
                toks.push(Tok::Any);
            } else {
                toks.push(Tok::Star);
            }
        } else {
            toks.push(Tok::Lit(c));
        }
    }
    let text: Vec<char> = path.chars().collect();
    // The optional `(?:.*/)?` prefix: start at 0, or after any `/` that no line terminator precedes.
    let mut starts = vec![0];
    for (i, c) in text.iter().enumerate() {
        if is_line_terminator(*c) {
            break;
        }
        if *c == '/' {
            starts.push(i + 1);
        }
    }
    starts.into_iter().any(|s| tok_matches(&toks, &text[s..]))
}

fn tok_matches(toks: &[Tok], text: &[char]) -> bool {
    let Some((tok, rest)) = toks.split_first() else { return text.is_empty() };
    match tok {
        Tok::Lit(c) => text.first() == Some(c) && tok_matches(rest, &text[1..]),
        Tok::Star => (0..=text.len()).take_while(|&k| k == 0 || text[k - 1] != '/').any(|k| tok_matches(rest, &text[k..])),
        Tok::Any => (0..=text.len()).take_while(|&k| k == 0 || !is_line_terminator(text[k - 1])).any(|k| tok_matches(rest, &text[k..])),
    }
}

/// Catalogue vendors one of whose file patterns matches the repo-relative `path`.
pub fn vendors_for_file(path: &str) -> Vec<&'static VendorDef> {
    VENDORS.iter().filter(|v| v.files.iter().any(|f| file_matches(f, path))).collect()
}

pub fn vendor_file_match(path: &str) -> bool {
    VENDORS.iter().any(|v| v.files.iter().any(|f| file_matches(f, path)))
}

/// Catalogue vendors that list the package (exact name, or prefix when the entry ends in `*`) for an OSV ecosystem.
pub fn package_vendor(ecosystem: &str, name: &str) -> Vec<&'static VendorDef> {
    VENDORS
        .iter()
        .filter(|v| {
            v.packages.for_ecosystem(ecosystem).iter().any(|p| match p.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => p == name,
            })
        })
        .collect()
}
