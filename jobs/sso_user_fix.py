from nautobot.apps.jobs import Job, register_jobs
from nautobot.users.models import User

class SSOUserFix(Job):
    class Meta:
        name = "Deduplicate SSO users"
        has_sensitive_variables = False
        description = '''
            When an SSO users logs in and there's already a local user with the
            same identity, a second user is created with a 16-character nonce.

            This job deletes the new user and re-associates the SSO identity
            to the correct username
        '''

    def deduplicate(self, nonce_user: User):
        try:
            real_user = User.objects.get(username=nonce_user.username[:-16])
        except User.DoesNotExist:
            self.logger.failure(f"Base user not found for {nonce_user.username}", extra={"object": nonce_user})

        social_auth = nonce_user.social_auth.all()

        for x in social_auth:
            x.user = real_user
            x.save()

        self.logger.success(f"Updated SSO login for {real_user.username}", extra={"object": real_user})

        nonce_user.delete()
        self.logger.info(
            f"Deleted user {nonce_user.username}", extra={"object": nonce_user}
        )

    def run(self):
        self.logger.info("Searching for users")

        duplicate_users = User.objects.filter(username__regex=".+[0-9a-f]{16}")

        for user in duplicate_users:
            self.deduplicate(user)


register_jobs(SSOUserFix)
