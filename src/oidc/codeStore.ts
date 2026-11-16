import crypto from 'node:crypto';

export interface AuthCode {
  clientId: string;
  redirectUri: string;
  userSub: string;
  sid: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  nonce?: string;
  scope: string;
  amr: string[];
  acr?: string;
  authTime: number;
}


export interface CodeStorage {
  save(key: string, value: string, ttlSeconds: number): Promise<unknown>;
  getdel(key: string): Promise<string | null>;
}

/** The atomic storage operation arbitrates all concurrent consumers. */
export function createCodeStore(storage: CodeStorage) {
  const key = (value: string) => `code:${value}`;
  return {
    async createCode(data: AuthCode): Promise<string> {
      const code = crypto.randomBytes(32).toString('base64url');
      await storage.save(key(code), JSON.stringify(data), 60);
      return code;
    },
    async consumeCode(code: string): Promise<AuthCode | null> {
      const raw = await storage.getdel(key(code));
      return raw ? JSON.parse(raw) as AuthCode : null;
    },
  };
}
