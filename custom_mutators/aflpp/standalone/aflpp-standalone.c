#include "afl-fuzz.h"
#include "afl-mutations.h"

typedef struct my_mutator {

  afl_state_t *afl;
  u8          *buf;
  u32          buf_size;

} my_mutator_t;

/**
 * @brief 自定义 AFL 初始化函数
 *
 * 根据给定的种子和 AFL 状态，初始化自定义的 my_mutator_t 结构体，并分配必要的内存空间。
 *
 * @param afl AFL 状态结构体指针
 * @param seed 种子值（在此函数中被忽略）
 *
 * @return 分配好的 my_mutator_t 结构体指针，如果分配失败则返回 NULL
 */
my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  // 忽略 seed 参数
  (void)seed;

  // 分配 my_mutator_t 结构体内存
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    // 分配内存失败，打印错误信息
    perror("afl_custom_init alloc");
    return NULL;

  }

  // 分配 buf 缓冲区内存
  if ((data->buf = malloc(1024*1024)) == NULL) {

    // 分配内存失败，打印错误信息
    perror("afl_custom_init alloc");
    return NULL;

  } else {

    // 设置 buf 缓冲区大小
    data->buf_size = 1024*1024;

  }

  /* fake AFL++ state */
  // 分配 afl_state_t 结构体内存，并设置一些模拟的 AFL++ 状态
  data->afl = calloc(1, sizeof(afl_state_t));
  data->afl->queue_cycle = 1;
  data->afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  // 打开 /dev/urandom 设备文件失败
  if (data->afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }
  // 设置随机种子
  rand_set_seed(data->afl, getpid());

  // 返回分配好的 my_mutator_t 结构体指针
  return data;

}

/* here we run the AFL++ mutator, which is the best! */

/**
 * @brief 自定义模糊测试函数
 *
 * 使用自定义的变异器对给定的缓冲区进行模糊测试，并返回变异后的数据。
 *
 * @param data 自定义变异器结构体指针
 * @param buf 原始缓冲区指针
 * @param buf_size 原始缓冲区大小
 * @param out_buf 变异后缓冲区指针的指针
 * @param add_buf 附加数据缓冲区指针
 * @param add_buf_size 附加数据缓冲区大小
 * @param max_size 最大缓冲区大小限制
 *
 * @return 变异后的数据大小
 */
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  // 如果最大大小超过了当前缓冲区的大小
  if (max_size > data->buf_size) {

    // 重新分配缓冲区大小
    u8 *ptr = realloc(data->buf, max_size);

    // 如果重新分配成功
    if (ptr) {

      // 返回0表示重新分配失败
      return 0;

    // 如果重新分配失败
    } else {

      // 更新缓冲区指针和大小
      data->buf = ptr;
      data->buf_size = max_size;

    }

  }

  // 生成随机变异步数
  u32 havoc_steps = 1 + rand_below(data->afl, 16);

  // 将原始数据复制到缓冲区
  /* set everything up, costly ... :( */
  memcpy(data->buf, buf, buf_size);

  // 进行变异操作
  /* the mutation */
  u32 out_buf_len = afl_mutate(data->afl, data->buf, buf_size, havoc_steps,
                               false, true, add_buf, add_buf_size, max_size);

  // 返回变异后的数据大小
  /* return size of mutated data */
  *out_buf = data->buf;
  return out_buf_len;

}

int main(int argc, char *argv[]) {

  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) {
    printf("Syntax: %s [-v] [inputfile [outputfile [splicefile]]]\n\n", argv[0]);
    printf("Reads a testcase from stdin when no input file (or '-') is specified,\n");
    printf("mutates according to AFL++'s mutation engine, and write to stdout when '-' or\n");
    printf("no output filename is given. As an optional third parameter you can give a file\n");
    printf("for splicing. Maximum input and output length is 1MB.\n");
    printf("The -v verbose option prints debug output to stderr.\n");
    return 0;
  }

  FILE *in = stdin, *out = stdout, *splice = NULL;
  unsigned char *inbuf = malloc(1024 * 1024), *outbuf, *splicebuf = NULL;
  int verbose = 0, splicelen = 0;

  if (argc > 1 && strcmp(argv[1], "-v") == 0) {
    verbose = 1;
    argc--;
    argv++;
    fprintf(stderr, "Verbose active\n");
  }

  my_mutator_t *data = afl_custom_init(NULL, 0);

  if (argc > 1 && strcmp(argv[1], "-") != 0) {
    if ((in = fopen(argv[1], "r")) == NULL) {
      perror(argv[1]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Input: %s\n", argv[1]);
  }

  size_t inlen = fread(inbuf, 1, 1024*1024, in);
  
  if (!inlen) {
    fprintf(stderr, "Error: empty file %s\n", argv[1] ? argv[1] : "stdin");
    return -1;
  }

  if (argc > 2 && strcmp(argv[2], "-") != 0) {
    if ((out = fopen(argv[2], "w")) == NULL) {
      perror(argv[2]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Output: %s\n", argv[2]);
  }

  if (argc > 3) {
    if ((splice = fopen(argv[3], "r")) == NULL) {
      perror(argv[3]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Splice: %s\n", argv[3]);
    splicebuf = malloc(1024*1024);
    size_t splicelen = fread(splicebuf, 1, 1024*1024, splice);
    if (!splicelen) {
      fprintf(stderr, "Error: empty file %s\n", argv[3]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Mutation splice length: %zu\n", splicelen);
  }

  if (verbose) fprintf(stderr, "Mutation input length: %zu\n", inlen);
  unsigned int outlen = afl_custom_fuzz(data, inbuf, inlen, &outbuf, splicebuf, splicelen, 1024*1024);

  if (outlen == 0 || !outbuf) {
    fprintf(stderr, "Error: no mutation data returned.\n");
    return -1;
  }

  if (verbose) fprintf(stderr, "Mutation output length: %u\n", outlen);

  if (fwrite(outbuf, 1, outlen, out) != outlen) {
    fprintf(stderr, "Warning: incomplete write.\n");
    return -1;
  }
  
  return 0;
}
