import { CookieOptions, NextFunction, Request, Response } from 'express';
import { Container } from 'typedi';
import { RequestWithUser } from '@interfaces/auth.interface';
import { User } from '@interfaces/users.interface';
import { AuthService } from '@services/auth.service';
import { CreateUserDto } from '@/dtos/users.dto';
import { omit } from 'lodash';
import redisClient from '@/redis/connectRedis';

export const excludedFields = ['password', 'verified', 'verificationCode'];

const cookiesOptions: CookieOptions = {
  httpOnly: true,
  sameSite: 'none',
  secure: true,
};

const accessTokenCookieOptions: CookieOptions = {
  ...cookiesOptions,
  expires: new Date(Date.now() + 60 * 60 * 1000),
  maxAge: 60 * 60 * 1000,
};
const logoutTokenCookieOptions: CookieOptions = {
  ...cookiesOptions,
  maxAge: -1,
};

export class AuthController {
  public auth = Container.get(AuthService);

  public signUp = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const userData: CreateUserDto = req.body;
      const signUpUserData: User = await this.auth.signup(userData);

      const userWithOmmitedFields = omit(signUpUserData, excludedFields);
      res.status(201).json({ data: userWithOmmitedFields, message: 'signup' });
    } catch (error) {
      next(error);
    }
  };

  public logIn = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const userData: User = req.body;
      const { accessToken, refreshToken } = await this.auth.login(userData);
      res.cookie('access_token', accessToken, accessTokenCookieOptions);
      res.cookie('refresh_token', refreshToken, accessTokenCookieOptions);
      res.cookie('logged_in', true, {
        ...accessTokenCookieOptions,
        httpOnly: false,
      });
      res.status(200).json({ status: 'success', accessToken });
    } catch (error) {
      next(error);
    }
  };

  public logOut = async (req: RequestWithUser, res: Response, next: NextFunction): Promise<void> => {
    try {
      await redisClient.del(res.locals.user.id);
      res.cookie('access_token', '', logoutTokenCookieOptions);
      res.cookie('refresh_token', '', logoutTokenCookieOptions);
      res.cookie('logged_in', '', logoutTokenCookieOptions);

      res.status(200).json({
        status: 'success',
      });
    } catch (error) {
      next(error);
    }
  };
}
