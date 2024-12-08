import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { DatabaseService } from 'src/database/database.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from './types/token-payload.interface';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly databaseService: DatabaseService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) { }

  async signup(data: Prisma.AuthCreateInput, response: Response) {
    const user = await this.getUser(data.email);
    if (user) {
      throw new ConflictException('User already exist');
    }

    await this.databaseService.auth.create({
      data: { ...data, password: bcrypt.hashSync(data.password, 10) },
    });

    const expiration = new Date()

    const tokenPayload: TokenPayload = {
      name: data.name,
      email: data.email
    }

    const accessToken = this.generateToken(
      tokenPayload,
      this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_SECRET'),
      +this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_EXPIRATION')
    );

    const refreshToken = this.generateToken(tokenPayload, this.configService.getOrThrow<string>("JWT_REFRESH_TOKEN_SECRET"), +this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION"))

    await this.databaseService.auth.update({
      where: {
        email: data.email
      }, data: {
        hashRt: await bcrypt.hash(refreshToken, 12)
      }
    })

    response.cookie("Authentication", accessToken, { httpOnly: true, secure: this.configService.get("NODE_ENV") === "production", expires: new Date(expiration.setMilliseconds(expiration.getMilliseconds() + parseInt(this.configService.getOrThrow<string>("JWT_ACCESS_TOKEN_EXPIRATION")))) })
    response.cookie("Refresh", refreshToken, { httpOnly: true, secure: this.configService.get("NODE_ENV") === "production", expires: new Date(expiration.setMilliseconds(expiration.getMilliseconds() + parseInt(this.configService.getOrThrow<string>("JWT_REFRESH_TOKEN_EXPIRATION")))) })

  }

  async login(data: Prisma.AuthCreateArgs["data"], response: Response) {
    const expiration = new Date()
    const user = await this.getUser(data.email);
    if (!user) {
      throw new NotFoundException('User does not exist');
    }

    const tokenPayload: TokenPayload = {
      name: user.name,
      email: user.email,
    };

    const accessToken = this.generateToken(
      tokenPayload,
      this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_SECRET'),
      +this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_EXPIRATION')
    );

    const refreshToken = this.generateToken(tokenPayload, this.configService.getOrThrow<string>("JWT_REFRESH_TOKEN_SECRET"), +this.configService.getOrThrow("JWT_REFRESH_TOKEN_EXPIRATION"))

    await this.databaseService.auth.update({
      where: {
        email: user.email
      }, data: {
        hashRt: await bcrypt.hash(refreshToken, 12)
      }
    })

    response.cookie("Authentication", accessToken, { httpOnly: true, secure: this.configService.get("NODE_ENV") === "production", expires: new Date(expiration.setMilliseconds(expiration.getMilliseconds() + parseInt(this.configService.getOrThrow<string>("JWT_ACCESS_TOKEN_EXPIRATION")))) })
    response.cookie("Refresh", refreshToken, { httpOnly: true, secure: this.configService.get("NODE_ENV") === "production", expires: new Date(expiration.setMilliseconds(expiration.getMilliseconds() + parseInt(this.configService.getOrThrow<string>("JWT_REFRESH_TOKEN_EXPIRATION")))) })
  }

  async logout(email: string, response: Response) {
    await this.databaseService.auth.update({
      where: {
        email: email,
        hashRt: {
          not: null
        }
      },
      data: {
        hashRt: null
      }
    })

    response.clearCookie("Authentication")
    response.clearCookie("Refresh")
  }

  async getUser(email: string) {
    return await this.databaseService.auth.findUnique({ where: { email } });
  }

  async verifyUser(email: string, password: string) {
    try {
      const user = await this.getUser(email);
      if (!user) {
        throw new NotFoundException('User not found');
      }

      const authenticate = await bcrypt.compare(password, user.password);
      if (!authenticate) {
        throw new UnauthorizedException();
      }
      return user;
    } catch (err) {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async verifyRefreshToken(refreshToken: string, email: string) {
    try {
      const user = await this.getUser(email)
      const authenticated = await bcrypt.compare(refreshToken, user.hashRt)

      if (!authenticated) {
        throw new UnauthorizedException()
      }

      return user
    } catch (error) {
      throw new UnauthorizedException("User not authenticated")
    }
  }

  generateToken(payload: any, secret: string, duration: number) {
    return this.jwtService.sign(payload, {
      secret,
      expiresIn: duration
    })
  }
}
