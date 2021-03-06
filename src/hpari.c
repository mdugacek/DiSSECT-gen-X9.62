#include <pari/pari.h>
#include <string.h>
#include <stdio.h>


void c_sqrtfp(const char* n_str, const char* p_str, char* out_str) {
    pari_init(100000000, 0);
    GEN n = gp_read_str(n_str);
    GEN p = gp_read_str(p_str);

    GEN res = Fp_sqrt(n, p);
    if (res == NULL) {
        pari_close();
        return;
    }

    char* out = GENtostr(res);
    strcpy(out_str, out);
    pari_close();
}

void c_points(const char* a_str, const char* b_str, const char* p_str, char* out_str) {
    pari_init(100000000, 0);
    GEN a = gp_read_str(a_str);
    GEN b = gp_read_str(b_str);
    GEN p = gp_read_str(p_str);

    GEN card = Fp_ellcard(a, b, p);

    char* out = GENtostr(card);
    strcpy(out_str, out);
    free(out);
    pari_close();
}
