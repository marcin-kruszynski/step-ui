import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

export async function GET() {
  // Return ENV value or null, client will use window.location.origin as fallback
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || null
  
  return NextResponse.json({ apiUrl })
}