## FILE internal
fopenは返り値としてFILE構造体のポインタを返す。基本的にプログラム上で扱うファイルはheap領域で確保されている。

```
FILE *fopen(const char *pathname, const char *mode);

:gdb
call fopen後
$rax   : 0x005555555592a0  →  0x00000000fbad2488

$ vmmap
0x00555555559000 0x0055555557a000 0x00000000000000 rw- [heap]

```

FILE構造体の定義は、libio/bits/types/struct_FILE.hにて定義されている。

_IO_FILEのマクロの存在には留意しておきたい。#ifdef _IO_USE_OLD_IO_FILEはfopenの時には無視されるので、_IO_FILE_complete内のいくつかの定義が合体している。

実際の定義とheapを照らし合わせてみると、次のようになる。

```
struct _IO_FILE
{
    int _flags;	               /* High-order word is _IO_MAGIC; rest is flags. */

    /* The following pointers correspond to the C++ streambuf protocol. */
    char *_IO_read_ptr;	       /* Current read pointer */
    char *_IO_read_end;	       /* End of get area. */
    char *_IO_read_base;	     /* Start of putback+get area. */
    char *_IO_write_base;	     /* Start of put area. */
    char *_IO_write_ptr;	     /* Current put pointer. */
    char *_IO_write_end;	     /* End of put area. */
    char *_IO_buf_base;	       /* Start of reserve area. */
    char *_IO_buf_end;	       /* End of reserve area. */

    /* The following fields are used to support backing up and undo. */
    char *_IO_save_base;       /* Pointer to start of non-current get area. */
    char *_IO_backup_base;     /* Pointer to first valid character of backup area */
    char *_IO_save_end;        /* Pointer to end of non-current get area. */

    struct _IO_marker *_markers;

    struct _IO_FILE *_chain;

    int _fileno;
    int _flags2;
    __off_t _old_offset;        /* This used to be _offset but it's too small.  */

    /* 1+column number of pbase(); 0 is unknown. */
    unsigned short _cur_column;
    signed char _vtable_offset; 
    char _shortbuf[1];

    _IO_lock_t *_lock;

/// _IO_USE_OLD_IO_FILEが定義されてないと
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
/// ここは無視される

  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};


0x555555559290: 0x00000000      0x00000000      0x000001e1      0x00000000
0x5555555592a0: 0xfbad2488      0x00000000      0x00000000      0x00000000
0x5555555592b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592c0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555592f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559300: 0x00000000      0x00000000      0xf7fa16a0      0x00007fff
0x555555559310: 0x00000003      0x00000000      0x00000000      0x00000000
0x555555559320: 0x00000000      0x00000000      0x55559380      0x00005555
0x555555559330: 0xffffffff      0xffffffff      0x00000000      0x00000000
0x555555559340: 0x55559390      0x00005555      0x00000000      0x00000000
0x555555559350: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559360: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559370: 0x00000000      0x00000000      0xf7f9d600      0x00007fff
0x555555559380: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559390: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593a0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593c0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x5555555593f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559400: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559410: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559420: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559430: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559440: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559450: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559460: 0x00000000      0x00000000      0x00000000      0x00000000
0x555555559470: 0xf7f9d0c0      0x00007fff      0x00020b91      0x00000000
```

fopenはstdio.hに定義されているが実はマクロであり、内部的には_IO_new_fopenを呼び出している。さらに言えばこの_IO_new_fopenもラップ関数でしかなく、本体は_fopen_internalとなる。

```
stdio.h 184行目
#define fopen(fname, mode) _IO_new_fopen (fname, mode)

ソース上では_fopne_internalの下に位置している
libio/iofopen.c 84行目
FILE *
_IO_new_fopen (const char *filename, const char *mode)
{
    return __fopen_internal (filename, mode, 1);
}

libio/iofopen.c 55行目
FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
    struct locked_FILE
    {
      struct _IO_FILE_plus fp;
  #ifdef _IO_MTSAFE_IO
      _IO_lock_t lock;
  #endif
      struct _IO_wide_data wd;
    } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

    if (new_f == NULL)
      return NULL;
  #ifdef _IO_MTSAFE_IO
    new_f->fp.file._lock = &new_f->lock;
  #endif
    _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
    _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
    _IO_new_file_init_internal (&new_f->fp);
    if (_IO_file_fopen ((FILE *) new_f, filename, mode, is32) != NULL)
      return __fopen_maybe_mmap (&new_f->fp.file);

    _IO_un_link (&new_f->fp);
    free (new_f);
    return NULL;
}
```
mallocを見てみると、確保されているサイズは_IO_FILEではなくlocked_FILE構造体のサイズになっている。このlocked_FILE内の_IO_FILE_plus構造体に_IO_FILEが定義されている。
```
struct locked_FILE
{
    struct _IO_FILE_plus fp;
    #ifdef _IO_MTSAFE_IO
      _IO_lock_t lock;
    #endif
    struct _IO_wide_data wd;
} 

/libio/libioP.h 325行目
struct _IO_FILE_plus
{
    FILE file;
    const struct _IO_jump_t *vtable;
};

/libio/libio.h 121行目
struct _IO_wide_data
{
    wchar_t *_IO_read_ptr;	  /* Current read pointer */
    wchar_t *_IO_read_end;	  /* End of get area. */
    wchar_t *_IO_read_base;	  /* Start of putback+get area. */
    wchar_t *_IO_write_base;	/* Start of put area. */
    wchar_t *_IO_write_ptr;	  /* Current put pointer. */
    wchar_t *_IO_write_end;	  /* End of put area. */
    wchar_t *_IO_buf_base;	  /* Start of reserve area. */
    wchar_t *_IO_buf_end;		  /* End of reserve area. */
    /* The following fields are used to support backing up and undo. */
    wchar_t *_IO_save_base;	  /* Pointer to start of non-current get area. */
    wchar_t *_IO_backup_base;	/* Pointer to first valid character of backup area */
    wchar_t *_IO_save_end;	  /* Pointer to end of non-current get area. */

    __mbstate_t _IO_state;
    __mbstate_t _IO_last_state;
    struct _IO_codecvt _codecvt;

    wchar_t _shortbuf[1];
  
    const struct _IO_jump_t *_wide_vtable;
};
```
差し当たってFSOPで重要なのは_IO_FILEのみであり、この辺りは気にする必要はなさそう。


## what's _IO_FILE
fopenでファイルを開くだけでは何をやっているのか掴めない。そこでfseekでファイルを少し操作してみる。

サンプルコードとテキストは以下の通り。
```
#include <stdio.h>
#include <stdlib.h>

int main() 
{
	char test[20] ;

	FILE *fp = fopen("test.txt", "r") ;
	if(fp == NULL){
		exit(1) ;
	}

	fseek(fp, 0xb, 0) ;

	return 0 ;
}

$ cat test.txt
this is structure
```
fseek後のheapは以下のようになる。
```
0x555555559290: 0x0000000000000000      0x00000000000001e1
0x5555555592a0: 0x00000000fbad2488      0x000055555555948b
0x5555555592b0: 0x000055555555948b      0x0000555555559480
0x5555555592c0: 0x0000555555559480      0x0000555555559480
0x5555555592d0: 0x0000555555559480      0x0000555555559480
0x5555555592e0: 0x000055555555a480      0x0000000000000000
0x5555555592f0: 0x0000000000000000      0x0000000000000000
0x555555559300: 0x0000000000000000      0x00007ffff7fa16a0
0x555555559310: 0x0000000000000003      0x0000000000000000
0x555555559320: 0x0000000000000000      0x0000555555559380
0x555555559330: 0x000000000000000b      0x0000000000000000
0x555555559340: 0x0000555555559390      0x0000000000000000
0x555555559350: 0x0000000000000000      0x0000000000000000
0x555555559360: 0x0000000000000000      0x0000000000000000
0x555555559370: 0x0000000000000000      0x00007ffff7f9d600
0x555555559380: 0x0000000000000000      0x0000000000000000
0x555555559390: 0x0000000000000000      0x0000000000000000
0x5555555593a0: 0x0000000000000000      0x0000000000000000
0x5555555593b0: 0x0000000000000000      0x0000000000000000
0x5555555593c0: 0x0000000000000000      0x0000000000000000
0x5555555593d0: 0x0000000000000000      0x0000000000000000
0x5555555593e0: 0x0000000000000000      0x0000000000000000
0x5555555593f0: 0x0000000000000000      0x0000000000000000
0x555555559400: 0x0000000000000000      0x0000000000000000
0x555555559410: 0x0000000000000000      0x0000000000000000
0x555555559420: 0x0000000000000000      0x0000000000000000
0x555555559430: 0x0000000000000000      0x0000000000000000
0x555555559440: 0x0000000000000000      0x0000000000000000
0x555555559450: 0x0000000000000000      0x0000000000000000
0x555555559460: 0x0000000000000000      0x0000000000000000
0x555555559470: 0x00007ffff7f9d0c0      0x0000000000001011
0x555555559480: 0x2073692073696874      0x0000000000727473
```
_IO_FLAGS構造体と照らし合わせてみる。

(ちなみにコンパイル時にデバッグ情報を渡すとこんな感じでfpが見れる。)
```
$ p/x *fp
_flags          = 0xfbad2488,
_IO_read_ptr    = 0x55555555948b,
_IO_read_end    = 0x55555555948b,
_IO_read_base   = 0x555555559480,
_IO_write_base  = 0x555555559480,
_IO_write_ptr   = 0x555555559480,
_IO_write_end   = 0x555555559480,
_IO_buf_base    = 0x555555559480,
_IO_buf_end     = 0x55555555a480,
_IO_save_base   = 0x0,
_IO_backup_base = 0x0,
_IO_save_end    = 0x0,
_markers        = 0x0,
_chain          = 0x7ffff7fa16a0,
_fileno         = 0x3,
_flags2         = 0x0,
_old_offset     = 0x0,
_cur_column     = 0x0,
_vtable_offset  = 0x0,
_shortbuf       = {0x0},
_lock           = 0x555555559380,
_offset         = 0xb,
_codecvt        = 0x0,
_wide_data      = 0x555555559390,
_freeres_list   = 0x0,
_freeres_buf    = 0x0,
__pad5          = 0x0,
_mode           = 0x0,
_unused2        = {0x0 <repeats 20 times>}
```