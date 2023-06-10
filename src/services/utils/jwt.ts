import jwt, { SignOptions } from 'jsonwebtoken';

export const signJwt = (payload: Object, keyValue: string, options: SignOptions) => {
  const privateKey = Buffer.from(keyValue, 'base64').toString('ascii');
  return jwt.sign(payload, privateKey, {
    ...options,
    algorithm: 'RS256',
  });
};

export const verifyJwt = <T>(token: string, keyValue: string): T | null => {
  try {
    const publicKey = Buffer.from(keyValue, 'base64').toString('ascii');
    const decoded = jwt.verify(token, publicKey) as T;

    return decoded;
  } catch (error) {
    return null;
  }
};
