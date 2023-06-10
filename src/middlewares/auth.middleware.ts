import { PrismaClient } from '@prisma/client';
import { NextFunction, Response } from 'express';
import { verify } from 'jsonwebtoken';
import { accessTokenPublicKey, SECRET_KEY } from '@config';
import { HttpException } from '@exceptions/httpException';
import { DataStoredInToken, RequestWithUser } from '@interfaces/auth.interface';
import { omit } from 'lodash';
import { verifyJwt } from '@/services/utils/jwt';
import redisClient from '@/redis/connectRedis';
import { excludedFields } from '@/controllers/auth.controller';

const getAuthorization = req => {
  const coockie = req.cookies['Authorization'];
  if (coockie) return coockie;

  const header = req.header('Authorization');
  if (header) return header.split('Bearer ')[1];

  return null;
};

export const AuthMiddleware = async (req: RequestWithUser, res: Response, next: NextFunction) => {
  try {
    let accessToken;
    const users = new PrismaClient().user;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      accessToken = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.access_token) {
      accessToken = req.cookies.access_token;
    }

    if (!accessToken) {
      return next(new HttpException(401, 'You are not logged in'));
    }

    // Validate the access token
    const decoded = verifyJwt<{ sub: string }>(accessToken, accessTokenPublicKey);

    if (!decoded) {
      return next(new HttpException(401, `Invalid token or user doesn't exist`));
    }

    // Check if the user has a valid session
    const session = await redisClient.get(decoded.sub);

    if (!session) {
      return next(new HttpException(401, `Invalid token or session has expired`));
    }

    // Check if the user still exist
    const user = await users.findUnique({ where: { id: JSON.parse(session).id } });

    if (!user) {
      return next(new HttpException(401, `Invalid token or session has expired`));
    }

    // Add user to res.locals
    res.locals.user = omit(user, excludedFields);

    next();
  } catch (err: any) {
    next(err);
  }
};
