/**
 * Copyright 2015 BitTechCenter Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.coinj.x11;

import fr.cryptohash.*;

import javax.annotation.concurrent.ThreadSafe;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Date: 5/16/15
 * Time: 1:21 AM
 *
 * @author Mikhail Kulikov
 */
@ThreadSafe
public final class X11Alg {

    private static final boolean NATIVE_LIBRARY_LOADED;

    private static final ThreadLocal<DigestContainer> digestContainersStorage = new ThreadLocal<DigestContainer>() {
        @Override
        protected DigestContainer initialValue() {
            return new DigestContainer();
        }
    };

    static {
        boolean load = false;
        try {
            System.loadLibrary("x11");
            load = true;
        } catch (Throwable ignore) {}
        NATIVE_LIBRARY_LOADED = load;
    }

    public static byte[] x11Digest(byte[] input) {
        checkNotNull(input);
        try {
            return NATIVE_LIBRARY_LOADED
                    ? nativeX11(input)
                    : x11(input);
        } catch (Exception ex) {
            throw new RuntimeException(ex); // unreachable
        }
    }

    private static native byte[] nativeX11(byte[] input);

    private static byte[] x11(byte[] header) {
        final DigestContainer digestContainer = digestContainersStorage.get();

        header = digestContainer.blake512.digest(header);
        header = digestContainer.bmw.digest(header);
        header = digestContainer.groestl.digest(header);
        header = digestContainer.skein.digest(header);
        header = digestContainer.jh.digest(header);
        header = digestContainer.keccak.digest(header);
        header = digestContainer.luffa.digest(header);
        header = digestContainer.cubehash.digest(header);
        header = digestContainer.shavite.digest(header);
        header = digestContainer.simd.digest(header);
        header = digestContainer.echo.digest(header);

        checkState(header.length == 64);

        final byte[] result = new byte[32];
        System.arraycopy(header, 0, result, 0, 32);
        return result;
    }

    private static final class DigestContainer {
        final BLAKE512 blake512 = new BLAKE512();
        final BMW512 bmw = new BMW512();
        final Groestl512 groestl = new Groestl512();
        final Skein512 skein = new Skein512();
        final JH512 jh = new JH512();
        final Keccak512 keccak = new Keccak512();
        final Luffa512 luffa = new Luffa512();
        final CubeHash512 cubehash = new CubeHash512();
        final SHAvite512 shavite = new SHAvite512();
        final SIMD512 simd = new SIMD512();
        final ECHO512 echo = new ECHO512();
    }

    private X11Alg() {}

}
