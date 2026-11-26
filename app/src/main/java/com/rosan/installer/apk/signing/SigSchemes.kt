// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.apk.signing

import androidx.annotation.IntDef

public class SigSchemes {
    @IntDef(flag = true, value = [
        SIG_SCHEME_V1,
        SIG_SCHEME_V2,
        SIG_SCHEME_V3,
        SIG_SCHEME_V4,
    ])
    public annotation class SignatureScheme

    companion object {
        const val SIG_SCHEME_V1 = 1 shl 0
        const val SIG_SCHEME_V2 = 1 shl 1
        const val SIG_SCHEME_V3 = 1 shl 2
        const val SIG_SCHEME_V4 = 1 shl 3

        const val TOTAL_SIG_SCHEME = 4

        const val DEFAULT_SCHEMES = SIG_SCHEME_V1 or SIG_SCHEME_V2
    }

    @SignatureScheme
    private var mFlags = 0

    constructor(@SignatureScheme flags: Int = 0) {
        mFlags = flags
    }

    fun isEmpty(): Boolean = mFlags == 0

    fun getFlags(): Int = mFlags

    fun setFlags(flags: Int) {
        mFlags = flags
    }

    fun getAllItems(): List<Int> = (0 until TOTAL_SIG_SCHEME).map { 1 shl it }

    fun v1SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V1) != 0
    fun v2SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V2) != 0
    fun v3SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V3) != 0
    fun v4SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V4) != 0
}
