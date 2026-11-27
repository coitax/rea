import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** RFC 6750 `Bearer` credentials; the scheme is case-insensitive, the token68 is not. */
const BEARER_AUTHORIZATION = /^bearer +([A-Za-z0-9\-._~+/]+=*)$/iu;

const digest = (text: string): Buffer =>
  createHash("sha256").update(text, "utf8").digest();

/** One listener's client credential: 32 random bytes, unpadded base64url, presented as `Authorization: Bearer`. */
export class BearerCredential {
  readonly value = randomBytes(32).toString("base64url");
  readonly #digest = digest(this.value);

  /** Compare fixed-length digests, so timing reveals neither the length nor a matching prefix. */
  admits(authorization: string | null): boolean {
    const presented =
      authorization === null
        ? undefined
        : BEARER_AUTHORIZATION.exec(authorization)?.[1];
    return (
      presented !== undefined &&
      timingSafeEqual(digest(presented), this.#digest)
    );
  }
}
