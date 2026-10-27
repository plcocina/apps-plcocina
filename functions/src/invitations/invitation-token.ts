import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type InvitationTokenMaterial = {
  token: string;
  hash: string;
  salt: string;
  keyVersion: number;
};

export class InvitationTokenKeyring {
  private readonly keys: ReadonlyMap<number, Buffer>;

  constructor(keys: ReadonlyMap<number, Uint8Array>, readonly activeVersion: number) {
    this.keys = new Map([...keys].map(([version, key]) => [version, Buffer.from(key)]));
    for (const [version, key] of this.keys) {
      if (!Number.isInteger(version) || version < 1 || key.byteLength < 32) {
        throw new Error("Cada clave de invitación debe tener versión positiva y al menos 256 bits.");
      }
    }
    if (!this.keys.has(activeVersion)) throw new Error("La versión activa de la clave no existe.");
  }

  issue(invitationId: string, generation = 1, salt = randomBytes(16).toString("base64url")): InvitationTokenMaterial {
    const key = this.keys.get(this.activeVersion);
    if (!key) throw new Error("La clave activa no está disponible.");
    const token = createHmac("sha256", key)
      .update(`invite\0${invitationId}\0${generation}\0${salt}`, "utf8")
      .digest("base64url");
    return { token, hash: this.hash(token), salt, keyVersion: this.activeVersion };
  }

  reconstruct(invitationId: string, generation: number, salt: string, keyVersion: number): string {
    const key = this.keys.get(keyVersion);
    if (!key) throw new Error("La versión de clave requerida ya no está disponible.");
    return createHmac("sha256", key)
      .update(`invite\0${invitationId}\0${generation}\0${salt}`, "utf8")
      .digest("base64url");
  }

  verify(token: string, expectedHash: string): boolean {
    const actual = Buffer.from(this.hash(token), "hex");
    const expected = Buffer.from(expectedHash, "hex");
    return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected);
  }

  private hash(token: string): string {
    return createHash("sha256").update(token, "utf8").digest("hex");
  }
}

export const INVITATION_PASSWORD_POLICY = Object.freeze({ minLength: 12, maxLength: 128 });
export const INVITATION_DEFAULT_HOURS = 72;
export const INVITATION_MAX_HOURS = 24 * 7;
export const INVITATION_CONFIRMATION_MINUTES = 10;
