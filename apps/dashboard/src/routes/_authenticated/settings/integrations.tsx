import { createFileRoute } from '@tanstack/react-router';
import { ArrowLeft } from 'lucide-react';
import { useTranslations } from 'use-intl';
import { listIntegrations } from '@/features/alert/api/queries';
import { IntegrationsList } from '@/features/alert/ui/components/integrations-list/integrations-list';
import { translator } from '@/shared/i18n/intl';
import { Link } from '@/shared/ui/components/link';
import { LoadFailure } from '@/shared/ui/components/load-failure';
import {
  integrationProjectId,
  integrationsBackHref,
} from './-components/integrations-back-link';

export const Route = createFileRoute('/_authenticated/settings/integrations')({
  validateSearch: (search: Record<string, unknown>) => ({
    projectId: integrationProjectId(search.projectId),
  }),
  head: () => {
    const t = translator('settings');
    return {
      meta: [
        { title: t('integrations.meta.title') },
        { name: 'description', content: t('integrations.meta.description') },
      ],
    };
  },
  loader: () => listIntegrations(),
  component: IntegrationsPage,
});

function IntegrationsPage() {
  const t = useTranslations('settings');
  const integrations = Route.useLoaderData();
  const { projectId } = Route.useSearch();

  return (
    <>
      <Link
        href={integrationsBackHref(projectId)}
        className="mb-4 inline-flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="size-4" />
        {projectId
          ? t('integrations.backToAlerts')
          : t('integrations.backToProjects')}
      </Link>

      <div className="mb-6 md:mb-8">
        <h1 className="text-xl md:text-2xl font-extrabold tracking-tight">
          {t('integrations.title')}
        </h1>
        <p className="text-muted-foreground mt-1 max-w-2xl">
          {t('integrations.subtitle')}
        </p>
      </div>

      {integrations.success ? (
        <IntegrationsList initialIntegrations={integrations.data} />
      ) : (
        <LoadFailure
          error={integrations.error}
          title={t('integrations.loadFailed')}
          notFoundOnMissing={false}
        />
      )}
    </>
  );
}
