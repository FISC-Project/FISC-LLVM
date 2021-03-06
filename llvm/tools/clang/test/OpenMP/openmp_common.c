// RUN: %clang_cc1 -verify -fopenmp -ferror-limit 100 -o - %s

#pragma omp // expected-error {{expected an OpenMP directive}}
#pragma omp unknown_directive // expected-error {{expected an OpenMP directive}}

void foo() {
#pragma omp // expected-error {{expected an OpenMP directive}}
#pragma omp unknown_directive // expected-error {{expected an OpenMP directive}}
}

typedef struct S {
#pragma omp parallel for private(j) schedule(static) if (tree1->totleaf > 1024) // expected-error {{unexpected OpenMP directive '#pragma omp parallel for'}}
} St;

