<p align="center">
  <img alt="GoReleaser Logo" src="https://storage.googleapis.com/trufflehog-static-sources/pixel_pig.png" height="140" />
  <h2 align="center">TruffleHog</h2>
  <p align="center">Find leaked credentials.</p>
</p>

---

<div align="center">

[![Go Report Card](https://goreportcard.com/badge/github.com/trufflesecurity/trufflehog/v3)](https://goreportcard.com/report/github.com/trufflesecurity/trufflehog/v3)
[![License](https://img.shields.io/badge/license-AGPL--3.0-brightgreen)](/LICENSE)
[![Total Detectors](https://img.shields.io/github/directory-file-count/trufflesecurity/truffleHog/pkg/detectors?label=Total%20Detectors&type=dir)](/pkg/detectors)

</div>

---

# :mag_right: _Now Scanning_

<div align="center">

<img src="assets/scanning_logos.svg">

**...and more**

</div>

# :loudspeaker: Join Our Community

Have questions? Feedback? Jump in slack or discord and hang out with us

Join our [Slack Community](https://join.slack.com/t/trufflehog-community/shared_invite/zt-pw2qbi43-Aa86hkiimstfdKH9UCpPzQ)

Join the [Secret Scanning Discord](https://discord.gg/8Hzbrnkr7E)

# :tv: Demo

![GitHub scanning demo](https://storage.googleapis.com/truffle-demos/non-interactive.svg)

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
```

# :floppy_disk: Installation

Several options available for you:

```bash
# MacOS users
brew install trufflehog

# Docker
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys

# Docker for M1 and M2 Mac
docker run --platform linux/arm64 --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys

# Binary releases
Download and unpack from https://github.com/trufflesecurity/trufflehog/releases

# Compile from source
git clone https://github.com/trufflesecurity/trufflehog.git
cd trufflehog; go install

# Using installation script
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Using installation script, verify checksum signature (requires cosign to be installed)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -v -b /usr/local/bin

# Using installation script to install a specific version
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin <ReleaseTag like v3.56.0>
```

# :closed_lock_with_key: Verifying the artifacts

Checksums are applied to all artifacts, and the resulting checksum file is signed using cosign.

You need the following tool to verify signature:

- [Cosign](https://docs.sigstore.dev/cosign/installation/)

Verification steps are as follow:

1. Download the artifact files you want, and the following files from the [releases](https://github.com/trufflesecurity/trufflehog/releases) page.

   - trufflehog\_{version}\_checksums.txt
   - trufflehog\_{version}\_checksums.txt.pem
   - trufflehog\_{version}\_checksums.txt.sig

2. Verify the signature:

   ```shell
   cosign verify-blob <path to trufflehog_{version}_checksums.txt> \
   --certificate <path to trufflehog_{version}_checksums.txt.pem> \
   --signature <path to trufflehog_{version}_checksums.txt.sig> \
   --certificate-identity-regexp 'https://github\.com/trufflesecurity/trufflehog/\.github/workflows/.+' \
   --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
   ```

3. Once the signature is confirmed as valid, you can proceed to validate that the SHA256 sums align with the downloaded artifact:

   ```shell
   sha256sum --ignore-missing -c trufflehog_{version}_checksums.txt
   ```

Replace `{version}` with the downloaded files version

Alternatively, if you are using installation script, pass `-v` option to perform signature verification.
This required Cosign binary to be installed prior to running installation script.

# :rocket: Quick Start

## 1: Scan a repo for only verified secrets

Command:

```bash
trufflehog git https://github.com/trufflesecurity/test_keys --only-verified
```

Expected output:

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAYVP4CIPPERUVIFXG
Line: 4
Commit: fbc14303ffbf8fb1c2c1914e8dda7d0121633aca
File: keys
Email: counter <counter@counters-MacBook-Air.local>
Repository: https://github.com/trufflesecurity/test_keys
Timestamp: 2022-06-16 10:17:40 -0700 PDT
...
```

## 2: Scan a GitHub Org for only verified secrets

```bash
trufflehog github --org=trufflesecurity --only-verified
```

## 3: Scan a GitHub Repo for only verified keys and get JSON output

Command:

```bash
trufflehog git https://github.com/trufflesecurity/test_keys --only-verified --json
```

Expected output:

```
{"SourceMetadata":{"Data":{"Git":{"commit":"fbc14303ffbf8fb1c2c1914e8dda7d0121633aca","file":"keys","email":"counter \u003ccounter@counters-MacBook-Air.local\u003e","repository":"https://github.com/trufflesecurity/test_keys","timestamp":"2022-06-16 10:17:40 -0700 PDT","line":4}}},"SourceID":0,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":2,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"AKIAYVP4CIPPERUVIFXG","Redacted":"AKIAYVP4CIPPERUVIFXG","ExtraData":{"account":"595918472158","arn":"arn:aws:iam::595918472158:user/canarytokens.com@@mirux23ppyky6hx3l6vclmhnj","user_id":"AIDAYVP4CIPPJ5M54LRCY"},"StructuredData":null}
...
```

## 4: Scan a GitHub Repo + its Issues and Pull Requests.

```bash
trufflehog github --repo=https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
```

## 5: Scan an S3 bucket for verified keys

```bash
trufflehog s3 --bucket=<bucket name> --only-verified
```

## 6: Scan S3 buckets using IAM Roles

```bash
trufflehog s3 --role-arn=<iam role arn>
```

## 7: Scan a Github Repo using SSH authentication in docker

```bash
docker run --rm -v "$HOME/.ssh:/root/.ssh:ro" trufflesecurity/trufflehog:latest git ssh://github.com/trufflesecurity/test_keys
```

## 8: Scan individual files or directories

```bash
trufflehog filesystem path/to/file1.txt path/to/file2.txt path/to/dir
```

## 9: Scan GCS buckets for verified secrets.

```bash
trufflehog gcs --project-id=<project-ID> --cloud-environment --only-verified
```

## 10: Scan a Docker image for verified secrets.

Use the `--image` flag multiple times to scan multiple images.

```bash
trufflehog docker --image trufflesecurity/secrets --only-verified
```

## 11: Scan in CI

Set the `--since-commit` flag to your default branch that people merge into (ex: "main"). Set the `--branch` flag to your PR's branch name (ex: "feature-1"). Depending on the CI/CD platform you use, this value can be pulled in dynamically (ex: [CIRCLE_BRANCH in Circle CI](https://circleci.com/docs/variables/) and [TRAVIS_PULL_REQUEST_BRANCH in Travis CI](https://docs.travis-ci.com/user/environment-variables/)). If the repo is cloned and the target branch is already checked out during the CI/CD workflow, then `--branch HEAD` should be sufficient. The `--fail` flag will return an 183 error code if valid credentials are found.

```bash
trufflehog git file://. --since-commit main --branch feature-1 --only-verified --fail
```

## 12: Scan a Postman workspace

Use the `--workspace`, `--collection`, `--environment` flags multiple times to scan multiple targets.

```bash
trufflehog postman --token=<postman api token> --workspace=<workspace id>
```

# :question: FAQ

- All I see is `🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷` and the program exits, what gives?
  - That means no secrets were detected
- Why is the scan taking a long time when I scan a GitHub org
  - Unauthenticated GitHub scans have rate limits. To improve your rate limits, include the `--token` flag with a personal access token
- It says a private key was verified, what does that mean?
  - Check out our Driftwood blog post to learn how to do this, in short we've confirmed the key can be used live for SSH or SSL [Blog post](https://trufflesecurity.com/blog/driftwood-know-if-private-keys-are-sensitive/)
- Is there an easy way to ignore specific secrets?
  - If the scanned source [supports line numbers](https://github.com/trufflesecurity/trufflehog/blob/d6375ba92172fd830abb4247cca15e3176448c5d/pkg/engine/engine.go#L358-L365), then you can add a `trufflehog:ignore` comment on the line containing the secret to ignore that secrets.

# :newspaper: What's new in v3?

TruffleHog v3 is a complete rewrite in Go with many new powerful features.

- We've **added over 700 credential detectors that support active verification against their respective APIs**.
- We've also added native **support for scanning GitHub, GitLab, Docker, filesystems, S3, GCS, Circle CI and Travis CI**.
- **Instantly verify private keys** against millions of github users and **billions** of TLS certificates using our [Driftwood](https://trufflesecurity.com/blog/driftwood) technology.
- Scan binaries, documents, and other file formats
- Available as a GitHub Action and a pre-commit hook

## What is credential verification?

For every potential credential that is detected, we've painstakingly implemented programmatic verification against the API that we think it belongs to. Verification eliminates false positives. For example, the [AWS credential detector](pkg/detectors/aws/aws.go) performs a `GetCallerIdentity` API call against the AWS API to verify if an AWS credential is active.

# :memo: Usage

TruffleHog has a sub-command for each source of data that you may want to scan:

- git
- github
- gitlab
- docker
- S3
- filesystem (files and directories)
- syslog
- circleci
- travisci
- GCS (Google Cloud Storage)

Each subcommand can have options that you can see with the `--help` flag provided to the sub command:

```
$ trufflehog git --help
usage: TruffleHog git [<flags>] <uri>

Find credentials in git repositories.

Flags:
  -h, --help                Show context-sensitive help (also try --help-long and --help-man).
      --debug               Run in debug mode.
      --trace               Run in trace mode.
      --profile             Enables profiling and sets a pprof and fgprof server on :18066.
  -j, --json                Output in JSON format.
      --json-legacy         Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.
      --github-actions      Output in GitHub Actions format.
      --concurrency=20           Number of concurrent workers.
      --no-verification     Don't verify the results.
      --only-verified       Only output verified results.
      --allow-verification-overlap
                                 Allow verification of similar credentials across detectors
      --filter-unverified   Only output first unverified result per chunk per detector if there are more than one results.
      --filter-entropy=FILTER-ENTROPY
                                 Filter unverified results with Shannon entropy. Start with 3.0.
      --config=CONFIG            Path to configuration file.
      --print-avg-detector-time
                                 Print the average time spent on each detector.
      --no-update           Don't check for updates.
      --fail                Exit with code 183 if results are found.
      --verifier=VERIFIER ...    Set custom verification endpoints.
      --custom-verifiers-only   Only use custom verification endpoints.
      --archive-max-size=ARCHIVE-MAX-SIZE
                                 Maximum size of archive to scan. (Byte units eg. 512B, 2KB, 4MB)
      --archive-max-depth=ARCHIVE-MAX-DEPTH
                                 Maximum depth of archive to scan.
      --archive-timeout=ARCHIVE-TIMEOUT
                                 Maximum time to spend extracting an archive.
      --include-detectors="all"  Comma separated list of detector types to include. Protobuf name or IDs may be used, as well as ranges.
      --exclude-detectors=EXCLUDE-DETECTORS
                                 Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.
      --version             Show application version.
  -i, --include-paths=INCLUDE-PATHS
                                 Path to file with newline separated regexes for files to include in scan.
  -x, --exclude-paths=EXCLUDE-PATHS
                                 Path to file with newline separated regexes for files to exclude in scan.
      --exclude-globs=EXCLUDE-GLOBS
                                 Comma separated list of globs to exclude in scan. This option filters at the `git log` level, resulting in faster scans.
      --since-commit=SINCE-COMMIT
                                 Commit to start scan from.
      --branch=BRANCH            Branch to scan.
      --max-depth=MAX-DEPTH      Maximum depth of commits to scan.
      --bare                Scan bare repository (e.g. useful while using in pre-receive hooks)

Args:
  <uri>  Git repository URL. https://, file://, or ssh:// schema expected.
```

For example, to scan a `git` repository, start with

```
$ trufflehog git https://github.com/trufflesecurity/trufflehog.git
```

## S3

The S3 source supports assuming IAM roles for scanning in addition to IAM users. This makes it easier for users to scan multiple AWS accounts without needing to rely on hardcoded credentials for each account.

The IAM identity that TruffleHog uses initially will need to have `AssumeRole` privileges as a principal in the [trust policy](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/) of each IAM role to assume.

To scan a specific bucket using locally set credentials or instance metadata if on an EC2 instance:

```bash
trufflehog s3 --bucket=<bucket-name>
```

To scan a specific bucket using an assumed role:

```bash
trufflehog s3 --bucket=<bucket-name> --role-arn=<iam-role-arn>
```

Multiple roles can be passed as separate arguments. The following command will attempt to scan every bucket each role has permissions to list in the S3 API:

```bash
trufflehog s3 --role-arn=<iam-role-arn-1> --role-arn=<iam-role-arn-2>
```

Exit Codes:

- 0: No errors and no results were found.
- 1: An error was encountered. Sources may not have completed scans.
- 183: No errors were encountered, but results were found. Will only be returned if `--fail` flag is used.

## :octocat: TruffleHog Github Action

### General Usage

```
on:
  push:
    branches:
      - main
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - name: Secret Scanning
      uses: trufflesecurity/trufflehog@main
      with:
        extra_args: --only-verified
```

In the example config above, we're scanning for live secrets in all PRs and Pushes to `main`. Only code changes in the referenced commits are scanned. If you'd like to scan an entire branch, please see the "Advanced Usage" section below.


### Shallow Cloning

If you're incorporating TruffleHog into a standalone workflow and aren't running any other CI/CD tooling alongside TruffleHog, then we recommend using [Shallow Cloning](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---depthltdepthgt) to speed up your workflow. Here's an example for how to do it:

```
...
      - shell: bash
        run: |
          if [ "${{ github.event_name }}" == "push" ]; then
            echo "depth=$(($(jq length <<< '${{ toJson(github.event.commits) }}') + 2))" >> $GITHUB_ENV
            echo "branch=${{ github.ref_name }}" >> $GITHUB_ENV
          fi
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            echo "depth=$((${{ github.event.pull_request.commits }}+2))" >> $GITHUB_ENV
            echo "branch=${{ github.event.pull_request.head.ref }}" >> $GITHUB_ENV
          fi
      - uses: actions/checkout@v3
        with:
          ref: ${{env.branch}}
          fetch-depth: ${{env.depth}}
      - uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
...
```

Depending on the event type (push or PR), we calculate the number of commits present. Then we add 2, so that we can reference a base commit before our code changes. We pass that integer value to the `fetch-depth` flag in the checkout action in addition to the relevant branch. Now our checkout process should be much shorter.

### Canary detection
TruffleHog statically detects [https://canarytokens.org/](https://canarytokens.org/) and lets you know when they're present without setting them off. You can learn more here: [https://trufflesecurity.com/canaries](https://trufflesecurity.com/canaries)

![image](https://github.com/trufflesecurity/trufflehog/assets/52866392/74ace530-08c5-4eaf-a169-84a73e328f6f)

### Advanced Usage

```yaml
- name: TruffleHog
  uses: trufflesecurity/trufflehog@main
  with:
    # Repository path
    path:
    # Start scanning from here (usually main branch).
    base:
    # Scan commits until here (usually dev branch).
    head: # optional
    # Extra args to be passed to the trufflehog cli.
    extra_args: --debug --only-verified
```

If you'd like to specify specific `base` and `head` refs, you can use the `base` argument (`--since-commit` flag in TruffleHog CLI) and the `head` argument (`--branch` flag in the TruffleHog CLI). We only recommend using these arguments for very specific use cases, where the default behavior does not work.

#### Advanced Usage: Scan entire branch
```
- name: scan-push
        uses: trufflesecurity/trufflehog@main
        with:
          base: ""
          head: ${{ github.ref_name }}
          extra_args: --only-verified
```

## Pre-commit Hook

TruffleHog can be used in a pre-commit hook to prevent credentials from leaking before they ever leave your computer.

**Key Usage Note:**

- **For optimal hook efficacy, execute `git add` followed by `git commit` separately.** This ensures TruffleHog analyzes all intended changes.
- **Avoid using `git commit -am`, as it might bypass pre-commit hook execution for unstaged modifications.**

An example `.pre-commit-config.yaml` is provided (see [pre-commit.com](https://pre-commit.com/) for installation).

```yaml
repos:
  - repo: local
    hooks:
      - id: trufflehog
        name: TruffleHog
        description: Detect secrets in your data.
        entry: bash -c 'trufflehog git file://. --since-commit HEAD --only-verified --fail'
        # For running trufflehog in docker, use the following entry instead:
        # entry: bash -c 'docker run --rm -v "$(pwd):/workdir" -i --rm trufflesecurity/trufflehog:latest git file:///workdir --since-commit HEAD --only-verified --fail'
        language: system
        stages: ["commit", "push"]
```

## Regex Detector (alpha)

TruffleHog supports detection and verification of custom regular expressions.
For detection, at least one **regular expression** and **keyword** is required.
A **keyword** is a fixed literal string identifier that appears in or around
the regex to be detected. To allow maximum flexibility for verification, a
webhook is used containing the regular expression matches.

TruffleHog will send a JSON POST request containing the regex matches to a
configured webhook endpoint. If the endpoint responds with a `200 OK` response
status code, the secret is considered verified.

**NB:** This feature is alpha and subject to change.

## Regex Detector Example

```yaml
# config.yaml
detectors:
  - name: HogTokenDetector
    keywords:
      - hog
    regex:
      hogID: '\b(HOG[0-9A-Z]{17})\b'
      hogToken: '[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
    verify:
      - endpoint: http://localhost:8000/
        # unsafe must be set if the endpoint is HTTP
        unsafe: true
        headers:
          - "Authorization: super secret authorization header"
```


```
$ trufflehog filesystem /tmp --config config.yaml --only-verified
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGAAIUNNWHAHJJWUQYR
File: /tmp/hog-facts.txt
```
Data structure sent to the custom verification server:

```
{
    "HogTokenDetector": {
        "HogID": ["HOGAAIUNNWHAHJJWUQYR"],
        "HogSecret": ["sD9vzqdSsAOxntjAJ/qZ9sw+8PvEYg0r7D1Hhh0C"],
    }
}
```

## Verification Server Example (Python)

Unless you run a verification server, secrets found by the custom regex
detector will be unverified. Here is an example Python implementation of a
verification server for the above `config.yaml` file.

```python
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

AUTH_HEADER = 'super secret authorization header'


class Verifier(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        try:
            if self.headers['Authorization'] != AUTH_HEADER:
                self.send_response(401)
                self.end_headers()
                return

            # read the body
            length = int(self.headers['Content-Length'])
            request = json.loads(self.rfile.read(length))
            self.log_message("%s", request)

            # check the match, you'll need to implement validateToken, which takes an array of ID's and Secrets
            if not validateTokens(request['HogTokenDetector']['hogID'], request['HogTokenDetector']['hogSecret']): 
                self.send_response(200)
                self.end_headers()
            else:
                # any other response besides 200
                self.send_response(406)
                self.end_headers()
        except Exception:
            self.send_response(400)
            self.end_headers()


with HTTPServer(('', 8000), Verifier) as server:
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
```

# :heart: Contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].

<a href="https://github.com/trufflesecurity/trufflehog/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=trufflesecurity/trufflehog" />
</a>

# :computer: Contributing

Contributions are very welcome! Please see our [contribution guidelines first](CONTRIBUTING.md).

We no longer accept contributions to TruffleHog v2, but that code is available in the `v2` branch.

## Adding new secret detectors

We have published some [documentation and tooling to get started on adding new secret detectors](hack/docs/Adding_Detectors_external.md). Let's improve detection together!

# Use as a library

Currently, trufflehog is in heavy development and no guarantees can be made on
the stability of the public APIs at this time.

# License Change

Since v3.0, TruffleHog is released under a AGPL 3 license, included in [`LICENSE`](LICENSE). TruffleHog v3.0 uses none of the previous codebase, but care was taken to preserve backwards compatibility on the command line interface. The work previous to this release is still available licensed under GPL 2.0 in the history of this repository and the previous package releases and tags. A completed CLA is required for us to accept contributions going forward.

# :money_with_wings: Enterprise product

Are you interested in continuously monitoring your Git, Jira, Slack, Confluence, etc.. for credentials? We have an enterprise product that can help. Reach out here to learn more https://trufflesecurity.com/contact/

We take the revenue from the enterprise product to fund more awesome open source projects that the whole community can benefit from.
