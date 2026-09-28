import { createFileRoute } from '@tanstack/react-router';
import { useTranslations } from 'use-intl';
import { getSsoLink } from '@/features/user/api/queries';
import { translator } from '@/shared/i18n/intl';
import { Link } from '@/shared/ui/components/link';
import { OutageScreen } from '@/shared/ui/components/outage-screen';
import { RustrakWordmark } from '@/shared/ui/components/rustrak-wordmark';
import { Button } from '@/shared/ui/components/shadcn/button';
import { LinkAccountForm } from './-components/link-account-form';

/**
 * Where an SSO login lands when its email already belongs to an account. The
 * server keeps the identity in the session until the account's password is
 * given, so this page only asks for that password.
 */
export const Route = createFileRoute('/link-account')({
  head: () => {
    const t = translator('auth');
    return { meta: [{ title: t('link.metaTitle') }] };
  },
  loader: () => getSsoLink(),
  component: LinkAccountPage,
});

function LinkAccountPage() {
  const t = useTranslations('auth');
  const result = Route.useLoaderData();

  if (!result.success && result.error.kind !== 'not_found') {
    return <OutageScreen error={result.error} />;
  }

  return (
    <div className="min-h-screen bg-card flex items-center justify-center p-8 lg:p-12">
      <div className="w-full max-w-[420px] space-y-10">
        <div className="flex items-center">
          <RustrakWordmark className="h-[22px] w-auto" />
        </div>

        {result.success ? (
          <LinkAccountForm
            email={result.data.email}
            provider={result.data.provider_name}
          />
        ) : (
          <div className="space-y-6">
            <div className="space-y-2">
              <h1 className="text-3xl font-bold tracking-tight">
                {t('link.expiredTitle')}
              </h1>
              <p className="text-muted-foreground">
                {t('link.expiredDescription')}
              </p>
            </div>
            <Button nativeButton={false} render={<Link href="/login" />}>
              {t('link.backToLogin')}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
