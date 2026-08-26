import { Body, Controller, Get, Put } from '@nestjs/common';
import { AppSettings, SettingsService } from './settings.service';

@Controller('settings')
export class SettingsController {
  constructor(private readonly settings: SettingsService) {}

  @Get()
  get() {
    return this.settings.get();
  }

  @Put()
  update(@Body() body: Partial<AppSettings>) {
    return this.settings.update(body);
  }
}
