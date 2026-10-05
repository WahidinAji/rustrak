export function integrationProjectId(value: unknown): number | undefined {
  // TanStack parses numeric query values into numbers on a direct page load.
  const id = typeof value === 'number' ? String(value) : value;
  if (typeof id !== 'string' || !/^[1-9]\d*$/.test(id)) {
    return undefined;
  }

  const parsed = Number(id);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

export function integrationsBackHref(projectId?: number): string {
  return projectId ? `/projects/${projectId}/settings/alerts` : '/projects';
}
