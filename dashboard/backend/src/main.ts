import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Every route is namespaced so the frontend can proxy /api to this service.
  app.setGlobalPrefix('api');

  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  // The dashboard is served from a different port in development.
  app.enableCors({
    origin: process.env.CORS_ORIGIN ?? true,
    methods: ['GET', 'POST', 'DELETE'],
  });

  const port = Number(process.env.PORT ?? 4000);
  await app.listen(port, '0.0.0.0');
  new Logger('Bootstrap').log(`ThreatWeave API listening on http://localhost:${port}/api`);
}

void bootstrap();
