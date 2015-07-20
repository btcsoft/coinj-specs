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

package org.coinj.scrypt;

import com.google.common.base.Preconditions;
import com.lambdaworks.crypto.SCrypt;

/**
 * Date: 4/30/15
 * Time: 8:54 PM
 *
 * @author Mikhail Kulikov
 */
public final class ScryptAlg {

    public static byte[] scryptDigest(byte[] input) {
        Preconditions.checkNotNull(input);
        try {
            return SCrypt.scrypt(input, input, 1024, 1, 1, 32);
        } catch (Exception e) {
            throw new RuntimeException(e); // can't happen
        }
    }

    private ScryptAlg() {}

}
