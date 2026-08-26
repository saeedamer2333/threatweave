import { Module } from '@nestjs/common';
import { FindingsController } from './findings/findings.controller';
import { FindingsService } from './findings/findings.service';
import { SuppressionsController } from './suppressions/suppressions.controller';
import { SuppressionsService } from './suppressions/suppressions.service';
import { EngineController } from './engine/engine.controller';
import { EngineService } from './engine/engine.service';
import { SettingsController } from './settings/settings.controller';
import { SettingsService } from './settings/settings.service';

@Module({
  controllers: [
    FindingsController,
    SuppressionsController,
    EngineController,
    SettingsController,
  ],
  providers: [
    FindingsService,
    SuppressionsService,
    EngineService,
    SettingsService,
  ],
})
export class AppModule {}
