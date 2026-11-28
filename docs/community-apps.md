# Community apps

Slipway can run apps other people publish, two ways:

- **A public GitHub repository, by URL.** Repositories → **Add by URL** takes `https://github.com/owner/project`,
  `owner/project` or an SSH remote. Slipway reads the repository with your linked GitHub account, else
  `SLIPWAY_GITHUB_SERVICE_TOKEN`, else anonymously (enough for a public repository), stores it by its GitHub
  id like a synced one, and detects its Dockerfile, compose file or `slipway.yml`. From then on it deploys like
  your own repositories. Adding the same repository again refreshes it. API: `POST /api/v1/repositories/import`
  with `{"url": "..."}` (needs `repos:sync`). Without any token GitHub allows about 60 requests an hour from one
  address, so on a busy install set a service token.
- **A container image.** Instances → Create Instance → **Container image** (or Repositories → **Run an image**)
  takes `nginx:1.27`, `linuxserver/jellyfin`, `lscr.io/linuxserver/jellyfin:latest`, `ghcr.io/owner/app:v2`,
  `name@sha256:…` or a `hub.docker.com` page. **Look up** reads the image's exposed ports, volumes and default
  variables from the registry and can fill in the port and volume mappings (check the host ports and volume names
  before deploying). API: `POST /api/v1/instances` with `"build_source": "image"`, `"image": "..."` and no
  `repository_id`; `GET /api/v1/images/inspect?ref=...` returns what the form shows.

## How an image is deployed

Each deploy resolves the tag to the image's digest on the registry (anonymously, as a public image allows), then
deploys a release whose Dockerfile is `FROM <image>@<digest>`: the host pulls exactly that image, and the
container runs with the instance's variables, ports, volumes and hostnames like a Dockerfile instance's. The
deployment's commit columns hold the first 40 hex digits of the digest, so the deployments list shows which image
ran; a retry deploys the digest its first attempt resolved. Deploy again to pick up a newer image behind the same
tag; change the tag on the instance's edit page to move to another version.

Only public images on registries Slipway knows are read: Docker Hub, GHCR, lscr.io, Quay, GCR, GitLab, ECR Public,
MCR and registry.k8s.io. `SLIPWAY_IMAGE_REGISTRIES=registry.example.com,other.example` adds others (they must
serve HTTPS and allow anonymous pulls). Private images and registry credentials are not supported yet.

An instance of an image can't be turned into one of a repository or the other way round, and images are standalone
instances only: an environment runs an app from a repository's `slipway.yml`.

## Trust

Both run code someone else wrote with the access you give it: a compose file can mount the host's filesystem,
and an image runs whatever its publisher built into it. Read a project's Dockerfile and compose file before you
deploy it, prefer a release tag to a moving branch, pin an image by tag or digest, and give a container only the
folders it needs.
