import { Request } from 'express';
import { User } from '@interfaces/users.interface';

export interface DataStoredInToken {
  id: number;
}

export interface TokenData {
  accessToken: string;
  refreshToken: string;
}

export interface RequestWithUser extends Request {
  user: User;
}
