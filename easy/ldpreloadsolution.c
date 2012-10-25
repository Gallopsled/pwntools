/* ldpreloadsolution.c
 *
 * gcc -fPIC -c ldpreloadsolution.c
 * ld -shared -o ldpreloadsolution.so -lc ldpreloadsolution.o
 * export LD_PRELOAD=/path/to/ldpreloadsolution.so
 * ./ldpreload
 */

int rand(void);

int rand(void) {
    return 4;
}
