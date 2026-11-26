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

    public companion object {
        public const val SIG_SCHEME_V1 = 1 shl 0
        public const val SIG_SCHEME_V2 = 1 shl 1
        public const val SIG_SCHEME_V3 = 1 shl 2
        public const val SIG_SCHEME_V4 = 1 shl 3

        public const val TOTAL_SIG_SCHEME = 4

        public const val DEFAULT_SCHEMES = SIG_SCHEME_V1 or SIG_SCHEME_V2
    }

    @SignatureScheme
    private var mFlags = 0

    constructor(@SignatureScheme flags: Int = 0) {
        this.mFlags = flags
    }

    public fun isEmpty(): Boolean = mFlags == 0

    public fun getFlags(): Int = mFlags

    public fun setFlags(flags: Int) {
        this.mFlags = flags
    }

    public fun getAllItems(): List<Int> {
        val allItems = mutableListOf<Int>()
        for (i in 0 until TOTAL_SIG_SCHEME) {
            allItems.add(1 shl i)
        }
        return allItems
    }

    public fun v1SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V1) != 0
    public fun v2SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V2) != 0
    public fun v3SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V3) != 0
    public fun v4SchemeEnabled(): Boolean = (mFlags and SIG_SCHEME_V4) != 0
}
