import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export class OrderService {
  /**
   * Hardcoded logic to replace the legacy trigger system.
   * When an order's status changes, we update all its order details to the new status.
   */
  async onOrderStatusChanged(orderId: string, newStatusId: number): Promise<void> {
    await prisma.orderDetail.updateMany({
      where: { orderId },
      data: { itemStatusId: Number(newStatusId) },
    });
  }
}
