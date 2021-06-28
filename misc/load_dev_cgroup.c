#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
  if (argc < 3) {
    printf("Usage: %s [objpath] [cgpath]\n", argv[0]);
    return 1;
  }
  char *objpath = argv[1];
  char *cgpath = argv[2];

  struct bpf_object *obj;
  int error = -1;
  int prog_fd, cgroup_fd;

  if (bpf_prog_load(objpath, BPF_PROG_TYPE_CGROUP_DEVICE,
        &obj, &prog_fd)) {
    printf("Failed to load DEV_CGROUP program\n");
    goto out;
  }

  cgroup_fd = open(cgpath, O_RDONLY);
  if (cgroup_fd < 0) {
    printf("Failed to open test cgroup\n");
    goto out;
  }

  if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_DEVICE, 0)) {
    printf("Failed to attach DEV_CGROUP program");
    goto out;
  }

  error = 0;

 out:
  return error;
}
