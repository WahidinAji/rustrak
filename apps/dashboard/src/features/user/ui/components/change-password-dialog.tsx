import { zodResolver } from '@hookform/resolvers/zod';
import { useState, useTransition } from 'react';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { useTranslations } from 'use-intl';
import { z } from 'zod';
import { changePassword } from '@/features/user/api/mutations';
import { applyServerFieldErrors } from '@/shared/lib/form-errors';
import { PasswordInput } from '@/shared/ui/components/password-input';
import { Button } from '@/shared/ui/components/shadcn/button';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/shared/ui/components/shadcn/dialog';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
  FormRootError,
} from '@/shared/ui/components/shadcn/form';

type ChangePasswordFormData = {
  current_password: string;
  new_password: string;
  confirm_password: string;
};

const EMPTY: ChangePasswordFormData = {
  current_password: '',
  new_password: '',
  confirm_password: '',
};

const FIELDS = [
  ['current_password', 'current', 'current-password'],
  ['new_password', 'new', 'new-password'],
  ['confirm_password', 'confirm', 'new-password'],
] as const;

/** The "Change password" button and the dialog it opens. */
export function ChangePasswordDialog() {
  const t = useTranslations('settings');
  const globalT = useTranslations();
  const [open, setOpen] = useState(false);
  const [isPending, startTransition] = useTransition();

  const form = useForm<ChangePasswordFormData>({
    resolver: zodResolver(
      z
        .object({
          current_password: z
            .string()
            .min(1, t('account.password.currentRequired')),
          new_password: z.string().min(1, t('account.password.newRequired')),
          confirm_password: z.string(),
        })
        .refine((data) => data.new_password === data.confirm_password, {
          path: ['confirm_password'],
          message: t('account.password.mismatch'),
        }),
    ),
    defaultValues: EMPTY,
  });

  // Typed passwords must not survive the dialog closing, whichever way it closes.
  const close = () => {
    form.reset(EMPTY);
    setOpen(false);
  };

  // Stays open while a request is in flight, so its outcome cannot land on a
  // later opening of the dialog.
  const onOpenChange = (next: boolean) => {
    if (next) setOpen(true);
    else if (!isPending) close();
  };

  const onSubmit = (data: ChangePasswordFormData) => {
    startTransition(async () => {
      const result = await changePassword({
        current_password: data.current_password,
        new_password: data.new_password,
      });

      if (!result.success) {
        applyServerFieldErrors(form, result.error, {
          labels: {
            current_password: t('account.password.current'),
            new_password: t('account.password.new'),
          },
          t: globalT,
        });
        return;
      }

      close();
      toast.success(t('account.password.changed'));
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger render={<Button variant="outline" />}>
        {t('account.password.change')}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('account.password.change')}</DialogTitle>
          <DialogDescription>
            {t('account.password.dialogDescription')}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form
            noValidate
            onSubmit={form.handleSubmit(onSubmit)}
            className="space-y-4"
          >
            {FIELDS.map(([name, label, autoComplete]) => (
              <FormField
                key={name}
                control={form.control}
                name={name}
                render={({ field }) => (
                  <FormItem className="space-y-2">
                    <FormLabel>{t(`account.password.${label}`)}</FormLabel>
                    <FormControl>
                      <PasswordInput
                        autoComplete={autoComplete}
                        disabled={isPending}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ))}

            {/* Where a failure that named no field of this form lands. */}
            <FormRootError />

            <DialogFooter>
              <DialogClose
                disabled={isPending}
                render={<Button variant="outline" type="button" />}
              >
                {t('account.password.cancel')}
              </DialogClose>
              <Button type="submit" disabled={isPending}>
                {isPending
                  ? t('account.password.submitting')
                  : t('account.password.submit')}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
