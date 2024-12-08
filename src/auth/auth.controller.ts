import { Body, Controller, Get, Post, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Prisma } from '@prisma/client';
import { CurrentUser } from './decorators/user.decroator';
import { Response } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtRefreshAuthGuard } from './guards/jwt-refresh-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Get("user")
  @UseGuards(JwtAuthGuard)
  user(@CurrentUser() user: Prisma.AuthCreateArgs["data"]) {
    return this.authService.getUser(user.email)
  }

  @Post("signup")
  signup(@Body() data: Prisma.AuthCreateInput, @Res({ passthrough: true }) response: Response) {
    return this.authService.signup(data, response);
  }

  @Post("login")
  @UseGuards(LocalAuthGuard)
  login(@CurrentUser() user: Prisma.AuthCreateArgs["data"], @Res({ passthrough: true }) response: Response) {
    return this.authService.login(user, response)
  }

  @Get("logout")
  @UseGuards(JwtAuthGuard)
  logout(@CurrentUser() user: Prisma.AuthCreateArgs["data"], @Res({ passthrough: true }) response: Response) {
    return this.authService.logout(user.email, response)
  }

  @Post("refresh")
  @UseGuards(JwtRefreshAuthGuard)
  async refresh(@CurrentUser() user: Prisma.AuthCreateArgs["data"], @Res({ passthrough: true }) response: Response) {
    return this.authService.login(user, response)
  }
}
