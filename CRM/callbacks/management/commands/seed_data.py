from django.core.management.base import BaseCommand
from faker import Faker
import random
from django.contrib.auth.models import User
from callbacks.models import Callback, UserProfile

class Command(BaseCommand):
    help = 'Seed the database with fake callback data'

    def handle(self, *args, **kwargs):
        fake = Faker()

        # Get all agent users from UserProfile
        agent_profiles = UserProfile.objects.filter(role='agent')
        agents = [profile.user for profile in agent_profiles]

        if not agents:
            self.stdout.write(self.style.ERROR('⚠️ No agent users found. Please create agent users first.'))
            return

        for _ in range(100000):  # Generate 1500 fake callbacks
            agent = random.choice(agents)
            Callback.objects.create(
                customer_name=fake.name(),
                address=fake.address(),
                phone_number=fake.phone_number(),
                email=fake.email(),
                website=fake.url(),
                remarks=fake.sentence(nb_words=6),
                notes=fake.text(max_nb_chars=100),
                created_by=agent,
                is_completed=random.choice([True, False]),
            )

        self.stdout.write(self.style.SUCCESS('✅ Successfully seeded fake callback records!'))
