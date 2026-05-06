import { BasePlugin } from './base.plugin';
import { SqlInjectionPlugin } from './sql-injection.plugin';
import { NoSqlInjectionPlugin } from './nosql-injection.plugin';
import { XssPlugin } from './xss.plugin';
import { SstiPlugin } from './ssti.plugin';
import { PrototypePollutionPlugin } from './prototype-pollution.plugin';
import { PluginId } from '../types';

const ALL_PLUGINS: BasePlugin[] = [
  new SqlInjectionPlugin(),
  new NoSqlInjectionPlugin(),
  new XssPlugin(),
  new SstiPlugin(),
  new PrototypePollutionPlugin(),
];

export function getPlugin(id: PluginId): BasePlugin | undefined {
  return ALL_PLUGINS.find((p) => p.id === id);
}

export function getPlugins(ids: PluginId[]): BasePlugin[] {
  return ids
    .map((id) => getPlugin(id))
    .filter((p): p is BasePlugin => p !== undefined);
}

export function getAllPlugins(): BasePlugin[] {
  return ALL_PLUGINS;
}

export function listPlugins(): { id: PluginId; name: string; description: string }[] {
  return ALL_PLUGINS.map((p) => ({
    id: p.id,
    name: p.name,
    description: p.description,
  }));
}
