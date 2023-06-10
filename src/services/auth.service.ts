import { PrismaClient } from '@prisma/client';
import { compare, hash } from 'bcrypt';
import { sign } from 'jsonwebtoken';
import { Service } from 'typedi';
import { redisCacheExpiresIn, SECRET_KEY, accessTokenExpiresIn, accessTokenPrivateKey, refreshTokenPrivateKey, refreshTokenExpiresIn } from '@config';
import { CreateUserDto, LoginUserDto } from '@dtos/users.dto';
import { HttpException } from '@exceptions/httpException';
import { DataStoredInToken, TokenData } from '@interfaces/auth.interface';
import { User } from '@interfaces/users.interface';
import crypto from 'crypto';
import redisClient from '@/redis/connectRedis';
import { signJwt } from './utils/jwt';

@Service()
export class AuthService {
  public users = new PrismaClient().user;

  public async signup(userData: CreateUserDto): Promise<User> {
    const findUser: User = await this.users.findUnique({ where: { email: userData.email } });
    if (findUser) throw new HttpException(409, `This email ${userData.email} already exists`);
    if (userData.confirmPassword !== userData.password) throw new HttpException(409, `Passwords do not match`);
    const hashedPassword = await hash(userData.password, 10);
    const verifyCode = crypto.randomBytes(32).toString('hex');
    const verificationCode = crypto.createHash('sha256').update(verifyCode).digest('hex');
    const createUserData: Promise<User> = this.users.create({
      data: {
        name: userData.name,
        role: 'user',
        email: userData.email,
        password: hashedPassword,
        verificationCode,
      },
    });
    return createUserData;
  }

  public async login(userData: LoginUserDto): Promise<{ accessToken: string, refreshToken: string }> {
    const findUser: User = await this.users.findUnique({ where: { email: userData.email } });
    if (!findUser) throw new HttpException(409, `This email ${userData.email} was not found`);

    const isPasswordMatching: boolean = await compare(userData.password, findUser.password);
    if (!isPasswordMatching) throw new HttpException(409, 'Password is not matching');

    const { accessToken, refreshToken } = this.createToken(findUser);

    return { accessToken, refreshToken };
  }

  public async logout(userData: User): Promise<User> {
    const findUser: User = await this.users.findFirst({ where: { email: userData.email, password: userData.password } });
    if (!findUser) throw new HttpException(409, "User doesn't exist");

    return findUser;
  }

  public createToken(user: User): TokenData {
    // 1. Create Session
    redisClient.set(`${user.id}`, JSON.stringify(user), {
      EX: +redisCacheExpiresIn * 60,
    });
    const accessToken = signJwt({ sub: user.id }, accessTokenPrivateKey, {
      expiresIn: `${accessTokenExpiresIn}m`,
    });
    const refreshToken = signJwt({ sub: user.id }, refreshTokenPrivateKey, {
      expiresIn: `${refreshTokenExpiresIn}m`,
    });

    return { accessToken, refreshToken };
  }

  public createCookie(tokenData: TokenData): string {
    return `Authorization=${tokenData.token}; HttpOnly; Max-Age=${tokenData.expiresIn};`;
  }
}
