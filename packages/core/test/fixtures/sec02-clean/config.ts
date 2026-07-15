// Secret read server-side only; only the publishable key is public.
export const stripeSecret = process.env.STRIPE_SECRET_KEY;
export const stripePublishable = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;
export const apiUrl = process.env.NEXT_PUBLIC_API_URL;
