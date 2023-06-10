import { IsEmail, IsString, IsNotEmpty, MinLength, MaxLength } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  public email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(32)
  public password: string;
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(32)
  public confirmPassword: string;
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(10)
  public name: string;
}

export class LoginUserDto {
  @IsEmail()
  public email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(32)
  public password: string;
}
export class UpdateUserDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(9)
  @MaxLength(32)
  public password: string;
}
