import { zodResolver } from '@hookform/resolvers/zod';
import { useTransition } from 'react';
import { useForm } from 'react-hook-form';
import { useTranslations } from 'use-intl';
import { z } from 'zod';
import { confirmSsoLink } from '@/features/user/api/mutations';
import { SERVER_ERROR_PATH } from '@/shared/lib/form-errors';
import { Link } from '@/shared/ui/components/link';
import { Button } from '@/shared/ui/components/shadcn/button';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormRootError,
} from '@/shared/ui/components/shadcn/form';
import { Input } from '@/shared/ui/components/shadcn/input';
import { Label } from '@/shared/ui/components/shadcn/label';
import { useRouter } from '@/shared/ui/hooks/use-router';

type LinkFormData = { password: string };

export function LinkAccountForm({
  email,
  provider,
}: {
  email: string;
  provider: string;
}) {
  const t = useTranslations('auth');
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  const form = useForm<LinkFormData>({
    resolver: zodResolver(
      z.object({ password: z.string().min(1, t('link.passwordRequired')) }),
    ),
    defaultValues: { password: '' },
  });

  const onSubmit = (data: LinkFormData) => {
    form.clearErrors();

    startTransition(async () => {
      const result = await confirmSsoLink(data.password);

      if (result.success) {
        router.push('/');
        return;
      }

      // Only a wrong password is a verdict on the field; everything else,
      // including an identity already linked elsewhere, goes under the form.
      if (result.error.kind === 'unauthenticated') {
        form.setError('password', {
          type: 'server',
          message: t('link.invalidPassword'),
        });
        return;
      }
      form.setError(SERVER_ERROR_PATH, {
        type: 'server',
        message:
          result.error.kind === 'conflict'
            ? t('link.alreadyLinked', { provider })
            : t('link.failure'),
      });
    });
  };

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">{t('link.title')}</h1>
        <p className="text-muted-foreground">
          {t('link.description', { email, provider })}
        </p>
      </div>

      <div className="space-y-2">
        <Label className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
          {t('link.emailLabel')}
        </Label>
        <Input value={email} readOnly disabled className="bg-background" />
      </div>

      <Form {...form}>
        <form
          noValidate
          onSubmit={form.handleSubmit(onSubmit)}
          className="space-y-4"
        >
          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem className="space-y-2">
                <FormLabel className="text-[11px] font-bold uppercase tracking-widest text-muted-foreground">
                  {t('link.passwordLabel')}
                </FormLabel>
                <FormControl>
                  <Input
                    type="password"
                    placeholder={t('link.passwordPlaceholder')}
                    autoComplete="current-password"
                    disabled={isPending}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormRootError />

          <Button
            type="submit"
            className="w-full font-extrabold uppercase tracking-widest text-xs py-6 mt-2"
            disabled={isPending}
          >
            {isPending ? t('link.submitting') : t('link.submit')}
          </Button>
        </form>
      </Form>

      <Button
        variant="ghost"
        className="w-full"
        nativeButton={false}
        render={<Link href="/login" />}
      >
        {t('link.cancel')}
      </Button>
    </div>
  );
}
