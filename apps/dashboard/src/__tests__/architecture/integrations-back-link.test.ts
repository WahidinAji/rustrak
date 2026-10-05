import { describe, expect, it } from 'vitest';
import {
  integrationProjectId,
  integrationsBackHref,
} from '../../routes/_authenticated/settings/-components/integrations-back-link';

// A project-origin search value must survive TanStack's numeric query parsing.
describe('integrationProjectId', () => {
  it('keeps a project id from the alert settings link', () => {
    expect(integrationsBackHref(integrationProjectId('3'))).toBe(
      '/projects/3/settings/alerts',
    );
    expect(integrationProjectId('3')).toBe(3);
    expect(integrationProjectId(3)).toBe(3);
  });

  it('uses the projects fallback when there is no project origin', () => {
    expect(integrationsBackHref(integrationProjectId(undefined))).toBe(
      '/projects',
    );
  });

  it.each(['0', '-1', '3abc', '/projects/3', '9007199254740992', 0, 3.5])(
    'rejects invalid project id %s',
    (value) => {
      expect(integrationProjectId(value)).toBeUndefined();
    },
  );
});
