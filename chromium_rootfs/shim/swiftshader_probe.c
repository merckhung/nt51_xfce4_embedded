/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * swiftshader_probe.c - Verify 32-bit ANGLE + SwiftShader Vulkan rendering
 * on Windows XP (NT 5.1) + Linux syscall shim.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef void *EGLDisplay;
typedef void *EGLConfig;
typedef void *EGLContext;
typedef void *EGLSurface;
typedef unsigned int EGLBoolean;
typedef int EGLint;
typedef intptr_t EGLAttrib;

#define EGL_DEFAULT_DISPLAY ((void *)0)
#define EGL_NO_DISPLAY ((EGLDisplay)0)
#define EGL_NO_CONTEXT ((EGLContext)0)
#define EGL_NO_SURFACE ((EGLSurface)0)
#define EGL_NONE 0x3038
#define EGL_RED_SIZE 0x3024
#define EGL_GREEN_SIZE 0x3023
#define EGL_BLUE_SIZE 0x3022
#define EGL_ALPHA_SIZE 0x3021
#define EGL_SURFACE_TYPE 0x3033
#define EGL_PBUFFER_BIT 0x0001
#define EGL_RENDERABLE_TYPE 0x3040
#define EGL_OPENGL_ES2_BIT 0x0004
#define EGL_WIDTH 0x3057
#define EGL_HEIGHT 0x3056
#define EGL_CONTEXT_CLIENT_VERSION 0x3098

#define EGL_PLATFORM_ANGLE_ANGLE 0x3202
#define EGL_PLATFORM_ANGLE_TYPE_ANGLE 0x3203
#define EGL_PLATFORM_ANGLE_TYPE_VULKAN_ANGLE 0x3450
#define EGL_PLATFORM_ANGLE_DEVICE_TYPE_ANGLE 0x3209
#define EGL_PLATFORM_ANGLE_DEVICE_TYPE_SWIFTSHADER_ANGLE 0x3487
#define EGL_PLATFORM_ANGLE_NATIVE_PLATFORM_TYPE_ANGLE 0x348F
#define EGL_PLATFORM_VULKAN_DISPLAY_MODE_HEADLESS_ANGLE 0x34A5

int main(void) {
    void *egl = dlopen("/opt/chromium/libEGL.so", RTLD_NOW | RTLD_GLOBAL);
    if (!egl) egl = dlopen("libEGL_test.so", RTLD_NOW | RTLD_GLOBAL);
    if (!egl) egl = dlopen("libEGL.so", RTLD_NOW | RTLD_GLOBAL);
    if (!egl) {
        fprintf(stderr, "[swiftshader-probe] dlopen libEGL.so failed: %s\n", dlerror());
        return 1;
    }
    void *gles = dlopen("/opt/chromium/libGLESv2.so", RTLD_NOW | RTLD_GLOBAL);
    if (!gles) gles = dlopen("/opt/chromium/libGLESv2_test.so", RTLD_NOW | RTLD_GLOBAL);
    if (!gles) gles = dlopen("libGLESv2_test.so", RTLD_NOW | RTLD_GLOBAL);
    if (!gles) gles = dlopen("libGLESv2.so", RTLD_NOW | RTLD_GLOBAL);
    if (!gles) {
        fprintf(stderr, "[swiftshader-probe] dlopen libGLESv2.so failed: %s\n", dlerror());
        return 1;
    }

    EGLDisplay (*eglGetPlatformDisplay)(unsigned int, void *, const EGLAttrib *) =
        dlsym(egl, "eglGetPlatformDisplay");
    EGLBoolean (*eglInitialize)(EGLDisplay, EGLint *, EGLint *) =
        dlsym(egl, "eglInitialize");
    EGLBoolean (*eglChooseConfig)(EGLDisplay, const EGLint *, EGLConfig *, EGLint, EGLint *) =
        dlsym(egl, "eglChooseConfig");
    EGLSurface (*eglCreatePbufferSurface)(EGLDisplay, EGLConfig, const EGLint *) =
        dlsym(egl, "eglCreatePbufferSurface");
    EGLContext (*eglCreateContext)(EGLDisplay, EGLConfig, EGLContext, const EGLint *) =
        dlsym(egl, "eglCreateContext");
    EGLBoolean (*eglMakeCurrent)(EGLDisplay, EGLSurface, EGLSurface, EGLContext) =
        dlsym(egl, "eglMakeCurrent");
    const unsigned char *(*glGetString)(unsigned int) =
        dlsym(gles, "glGetString");
    void (*glClearColor)(float, float, float, float) =
        dlsym(gles, "glClearColor");
    void (*glClear)(unsigned int) =
        dlsym(gles, "glClear");
    void (*glReadPixels)(int, int, int, int, unsigned int, unsigned int, void *) =
        dlsym(gles, "glReadPixels");

    if (!eglGetPlatformDisplay || !eglInitialize || !eglChooseConfig ||
        !eglCreatePbufferSurface || !eglCreateContext || !eglMakeCurrent ||
        !glGetString || !glClearColor || !glClear || !glReadPixels) {
        fprintf(stderr, "[swiftshader-probe] missing EGL/GLES symbols\n");
        return 2;
    }

    const EGLAttrib disp_attrs[] = {
        EGL_PLATFORM_ANGLE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_TYPE_VULKAN_ANGLE,
        EGL_PLATFORM_ANGLE_DEVICE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_DEVICE_TYPE_SWIFTSHADER_ANGLE,
        EGL_PLATFORM_ANGLE_NATIVE_PLATFORM_TYPE_ANGLE, EGL_PLATFORM_VULKAN_DISPLAY_MODE_HEADLESS_ANGLE,
        EGL_NONE
    };
    EGLDisplay dpy = eglGetPlatformDisplay(EGL_PLATFORM_ANGLE_ANGLE, EGL_DEFAULT_DISPLAY, disp_attrs);
    if (dpy == EGL_NO_DISPLAY) {
        fprintf(stderr, "[swiftshader-probe] eglGetPlatformDisplay failed\n");
        return 2;
    }

    EGLint major = 0, minor = 0;
    if (!eglInitialize(dpy, &major, &minor)) {
        fprintf(stderr, "[swiftshader-probe] eglInitialize failed\n");
        return 3;
    }
    fprintf(stderr, "[swiftshader-probe] eglInitialize OK (%d.%d)\n", (int)major, (int)minor);

    const EGLint cfg_attrs[] = {
        EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_ALPHA_SIZE, 8,
        EGL_NONE
    };
    EGLConfig cfg = 0;
    EGLint num_cfg = 0;
    if (!eglChooseConfig(dpy, cfg_attrs, &cfg, 1, &num_cfg) || num_cfg < 1) {
        fprintf(stderr, "[swiftshader-probe] eglChooseConfig failed\n");
        return 4;
    }

    const EGLint pbuf_attrs[] = { EGL_WIDTH, 64, EGL_HEIGHT, 64, EGL_NONE };
    EGLSurface surf = eglCreatePbufferSurface(dpy, cfg, pbuf_attrs);
    const EGLint ctx_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext ctx = eglCreateContext(dpy, cfg, EGL_NO_CONTEXT, ctx_attrs);
    if (!eglMakeCurrent(dpy, surf, surf, ctx)) {
        fprintf(stderr, "[swiftshader-probe] eglMakeCurrent failed\n");
        return 5;
    }

    const char *vendor = (const char *)glGetString(0x1F00);
    const char *renderer = (const char *)glGetString(0x1F01);
    const char *version = (const char *)glGetString(0x1F02);

    glClearColor(0.2f, 0.8f, 0.4f, 1.0f);
    glClear(0x00004000);
    unsigned char pixel[4] = {0, 0, 0, 0};
    glReadPixels(32, 32, 1, 1, 0x1908 /* GL_RGBA */, 0x1401 /* GL_UNSIGNED_BYTE */, pixel);

    if (!renderer || !strstr(renderer, "SwiftShader") ||
        pixel[0] != 51 || pixel[1] != 204 || pixel[2] != 102 || pixel[3] != 255) {
        fprintf(stderr, "[swiftshader-probe] FAILED vendor=%s renderer=%s rgba=%u,%u,%u,%u\n",
                vendor ? vendor : "null", renderer ? renderer : "null",
                pixel[0], pixel[1], pixel[2], pixel[3]);
        return 6;
    }

    printf("[swiftshader-probe] PASS vendor=\"%s\" renderer=\"%s\" version=\"%s\" rgba=%u,%u,%u,%u\n",
           vendor ? vendor : "", renderer, version ? version : "",
           pixel[0], pixel[1], pixel[2], pixel[3]);
    fflush(stdout);
    return 0;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    exit(main());
}
