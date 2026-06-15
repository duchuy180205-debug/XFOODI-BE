import { Router, type Router as IRouter } from 'express';
import crypto from 'crypto';

const router: IRouter = Router();

const mockTenant = {
  id: crypto.randomUUID(),
  name: "Demo Restaurant",
  hostname: "demo",
  businessName: "Demo Restaurant Ltd",
  logoUrl: "https://placehold.co/400x100?text=Demo+Restaurant",
  faviconUrl: "https://placehold.co/32x32?text=D",
  backgroundUrl: "https://placehold.co/1920x1080?text=Background",
  primaryColor: "#FF380B",
  lightBaseColor: "#FFFFFF",
  lightSurfaceColor: "#F9FAFB",
  lightCardColor: "#FFFFFF",
  darkBaseColor: "#0A0E14",
  darkSurfaceColor: "#1A1F2E",
  darkCardColor: "#151A24",
  status: true,
  aboutUs: "We are the best restaurant in town.",
  businessPrimaryPhone: "0123456789",
  businessEmailAddress: "contact@demo.restx.food",
  businessAddressLine1: "123 Main St",
  businessCountry: "VN",
  createdDate: new Date().toISOString(),
  tenantSettings: []
};

router.get('/', (req, res) => {
  res.json([mockTenant]);
});

router.get('/:domain', (req, res) => {
  const { domain } = req.params;
  
  // Return mock tenant for any domain to make testing easy
  res.json({
    ...mockTenant,
    hostname: domain
  });
});

router.get('/:id/business-hours', (req, res) => {
  const hours = Array.from({ length: 7 }, (_, i) => ({
    dayOfWeek: i,
    openTime: "09:00:00",
    closeTime: "22:00:00",
    isClosed: false
  }));
  res.json(hours);
});

router.get('/:id/payment-settings', (req, res) => {
  res.status(404).json({ success: false, message: "Payment settings not configured" });
});

router.get('/requests', (req, res) => {
  res.json([]);
});

router.post('/requests', (req, res) => {
  res.json(crypto.randomUUID());
});

export default router;
