import { Body, Controller, Delete, Get, Param, Post, Query } from '@nestjs/common';
import { SuppressionsService, SuppressionRule } from './suppressions.service';

@Controller('suppressions')
export class SuppressionsController {
  constructor(private readonly suppressions: SuppressionsService) {}

  @Get()
  list(@Query('all') all?: string) {
    return this.suppressions.list(all === 'true');
  }

  /** Called by the dashboard's Dismiss action. */
  @Post()
  create(@Body() body: Partial<SuppressionRule>) {
    return this.suppressions.create(body);
  }

  @Delete(':id')
  revoke(@Param('id') id: string) {
    return this.suppressions.revoke(id);
  }

  @Post(':id/restore')
  restore(@Param('id') id: string) {
    return this.suppressions.restore(id);
  }
}
