export type Locale = 'mn' | 'en';
export type UserRole = 'user' | 'admin';

export type Disease = {
  id: string;
  slug: string;
  name: string;
  aliases: string[];
  category: string;
  shortDescription: string;
  summaryMedical: string;
  summarySimple: string;
  causes: { title: string; description: string; image?: string }[];
  symptoms: {
    medicalTerm: string;
    description: string;
    synonyms?: string[];
    frequency?: string;
    bodySystem?: string;
  }[];
  references?: { title: string; url: string }[];
  locale: Locale;
  published: boolean;
  updatedAt: string;
};

export type DailyCornerEntry = {
  id: string;
  date: string;
  title: string;
  quote?: string;
  body: string;
  reminderTitle?: string;
  reminderBody?: string;
  image?: string;
  audioUrl?: string;
  locale: Locale;
  published: boolean;
};

export type EventItem = {
  id: string;
  title: string;
  summary: string;
  description?: string;
  date: string;
  startTime?: string;
  endTime?: string;
  organizer?: string;
  location?: string;
  image?: string;
  link?: string;
  locale: Locale;
  published: boolean;
};

export type EventRegistrationForm = {
  name: string;
  email: string;
  phone?: string;
  attendees: number;
  note?: string;
};

export type DonationForm = {
  donationType: 'one_time' | 'monthly';
  amount: number;
  dedicateTo?: string;
  note?: string;
  firstName: string;
  lastName: string;
  address: string;
  country: string;
  stateProvince: string;
  city: string;
  postalCode: string;
  email: string;
  phone?: string;
  paymentType: 'credit_card' | 'qpay';
  consentAccepted: boolean;
  captchaPassed: boolean;
};

export type ContactForm = {
  name: string;
  email: string;
  subject: string;
  message: string;
};

export type AuthUser = {
  id: string;
  username: string;
  name: string;
  email: string;
  role: UserRole;
  profileImageUrl?: string;
  createdAt: string;
};

export type UpdateProfileForm = {
  name: string;
  profileImageUrl?: string;
};

export type LoginForm = {
  identifier: string;
  password: string;
};

export type RegisterForm = {
  name: string;
  email: string;
  password: string;
};

export type AuthResponse = {
  token: string;
  user: AuthUser;
};

export type AdminUser = AuthUser;

export type AdminCreateUserForm = {
  name: string;
  username: string;
  email: string;
  password: string;
};

export type AdminUpdateUserForm = {
  username: string;
  role: UserRole;
  password?: string;
};

export type AdminEventForm = {
  locale: Locale;
  title: string;
  summary: string;
  description?: string;
  date: string;
  startTime?: string;
  endTime?: string;
  organizer?: string;
  location?: string;
  image?: string;
  link?: string;
  published: boolean;
};

export type AdminDailyCornerForm = {
  locale: Locale;
  date: string;
  title: string;
  quote?: string;
  body: string;
  reminderTitle?: string;
  reminderBody?: string;
  image?: string;
  audioUrl?: string;
  published: boolean;
};

export type AdminDiseaseCauseForm = {
  title: string;
  description: string;
  image?: string;
};

export type AdminDiseaseSymptomForm = {
  medicalTerm: string;
  description: string;
  synonyms?: string[];
  frequency?: string;
  bodySystem?: string;
};

export type AdminDiseaseReferenceForm = {
  title: string;
  url: string;
};

export type AdminDiseaseForm = {
  locale: Locale;
  slug: string;
  name: string;
  aliases: string[];
  category: string;
  shortDescription: string;
  summaryMedical: string;
  summarySimple: string;
  causes: AdminDiseaseCauseForm[];
  symptoms: AdminDiseaseSymptomForm[];
  references: AdminDiseaseReferenceForm[];
  published: boolean;
};
