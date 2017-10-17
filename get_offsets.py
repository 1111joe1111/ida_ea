from subprocess import Popen, PIPE, call, check_output
from time import sleep
from re import search
from sys import maxsize

# make temp c programme to find c library offsets
with open("/tmp/tmp_offsets.c", "w") as w:
    w.write("void main(){}")

if not maxsize > 2**32:
    print "Warning: Running 32bit Python. May not be able to calculate required offsets for 64bit programmes"


def get_offsets(bits):

    try:
        call("gcc /tmp/tmp_offsets.c -m%s -o /tmp/tmp_offsets" % bits, shell=True, stderr=PIPE)

    except:
        if bits == 32:
            print ("Warning: Couldn't compile temp C program for x86 architecture.\n"
                   "If you are on x64 try installing mulitlib (sudo apt-get install gcc-multilib on Debian)\n"
                   "to resolve this.\n"
                   "If you are only debugging 64bit programs, ignore this warning and use only 64bit offsets.")
        else:
            print ("Warning: Could not compile temp C program for x64 architecture.\n"
                   "If on 32bit system ignore this warning and use only 32bit offsets")
        return


    p = Popen("gdb -q /tmp/tmp_offsets", shell=True,stdin=PIPE, stdout=PIPE)

    sleep(0.5)
    p.stdin.write("b main\nr\n")
    sleep(0.5)

    p.stdin.write(
        "info proc mappings\n"
        "q\n"
        "y\n"
    )

    main_arena, malloc = [int(i, 16) for i in check_output("nm " + "/usr/lib/debug" + search("(/.*libc-.*\.so)", p.stdout.read()).group(1) +
                                                           " | grep 'main_arena\| __libc_malloc$' | awk '{print $1}'", shell=True).split("\n") if i]

    print "%s-bit offsets" % bits
    print "main_arena: " + hex(main_arena)
    print "malloc: " + hex(malloc)
    print


print "Calculating Required Offsets\n"
get_offsets(32)
get_offsets(64)
