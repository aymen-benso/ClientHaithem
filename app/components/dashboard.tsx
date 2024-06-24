
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card"
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table"
import { ResponsiveLine } from "@nivo/line"
import { ResponsivePie } from "@nivo/pie"
import { ResponsiveBar } from "@nivo/bar"

export function Dashboard() {
  return (
    <div className="flex flex-col w-full min-h-screen">
      <header className="flex items-center h-16 px-4 border-b shrink-0 md:px-6">
        <Link href="#" className="flex items-center gap-2 text-lg font-semibold sm:text-base mr-4" prefetch={false}>
          <ShieldIcon className="w-6 h-6" />
          <span>Network Security Dashboard</span>
        </Link>
        <nav className="hidden font-medium sm:flex flex-row items-center gap-5 text-sm lg:gap-6">
          <Link href="#" className="text-muted-foreground" prefetch={false}>
            Overview
          </Link>
          <Link href="#" className="text-muted-foreground" prefetch={false}>
            Traffic Analysis
          </Link>
          <Link href="#" className="font-bold" prefetch={false}>
            Threat Detection
          </Link>
          <Link href="#" className="text-muted-foreground" prefetch={false}>
            Alerts
          </Link>
          <Link href="#" className="text-muted-foreground" prefetch={false}>
            Settings
          </Link>
        </nav>
        <div className="flex items-center w-full gap-4 md:ml-auto md:gap-2 lg:gap-4">
          <Button variant="ghost" size="icon" className="rounded-full ml-auto">
            <img src="/placeholder.svg" width="32" height="32" className="rounded-full border" alt="Avatar" />
            <span className="sr-only">Toggle user menu</span>
          </Button>
        </div>
      </header>
      <main className="flex min-h-[calc(100vh_-_theme(spacing.16))] bg-muted/40 flex-1 flex-col gap-4 p-4 md:gap-8 md:p-10">
        <div className="max-w-6xl w-full mx-auto grid gap-2">
          <h1 className="text-3xl font-bold tracking-tight">Network Security Dashboard</h1>
          <p className="text-muted-foreground flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-[#09CE6B] rounded-full animate-ping duration-[5000]" />
            Real-time threat detection and network monitoring
          </p>
        </div>
        <div className="grid gap-6 max-w-6xl w-full mx-auto">
          <div className="grid gap-6 lg:grid-cols-3">
            <Card className="relative overflow-hidden">
              <CardHeader className="flex flex-row items-center border-b">
                <CardTitle>Traffic Volume</CardTitle>
                <CardDescription className="ml-auto">
                  <ActivityIcon className="w-4 h-4 mr-1" />
                  Live
                </CardDescription>
              </CardHeader>
              <CardContent>
                <LineChart className="aspect-[9/4]" />
              </CardContent>
            </Card>
            <Card className="relative overflow-hidden">
              <CardHeader className="flex flex-row items-center border-b">
                <CardTitle>Top Source IPs</CardTitle>
                <CardDescription className="ml-auto">
                  <ActivityIcon className="w-4 h-4 mr-1" />
                  Live
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4 text-sm p-6">
                <div className="flex items-center">
                  <div>192.168.1.100</div>
                  <div className="font-semibold ml-auto">3K</div>
                </div>
                <div className="flex items-center">
                  <div>10.0.0.5</div>
                  <div className="font-semibold ml-auto">1.2K</div>
                </div>
                <div className="flex items-center">
                  <div>172.16.0.50</div>
                  <div className="font-semibold ml-auto">1.1K</div>
                </div>
                <div className="flex items-center">
                  <div>192.168.2.25</div>
                  <div className="font-semibold ml-auto">1K</div>
                </div>
                <div className="flex items-center">
                  <div>10.0.0.12</div>
                  <div className="font-semibold ml-auto">1K</div>
                </div>
              </CardContent>
            </Card>
            <Card className="relative overflow-hidden">
              <CardHeader className="flex flex-row items-center border-b">
                <CardTitle>Threat Types</CardTitle>
                <CardDescription className="ml-auto">
                  <ActivityIcon className="w-4 h-4 mr-1" />
                  Live
                </CardDescription>
              </CardHeader>
              <CardContent>
                <PieChart className="aspect-[9/4]" />
              </CardContent>
            </Card>
          </div>
          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="relative overflow-hidden">
              <CardHeader className="flex flex-row items-center border-b">
                <CardTitle>Threat Trends</CardTitle>
                <CardDescription className="ml-auto">
                  <ActivityIcon className="w-4 h-4 mr-1" />
                  Live
                </CardDescription>
              </CardHeader>
              <CardContent>
                <StackedbarChart className="aspect-[9/4]" />
              </CardContent>
            </Card>
            <Card className="relative overflow-hidden">
              <CardHeader className="flex flex-row items-center border-b">
                <CardTitle>Threat Intelligence</CardTitle>
                <CardDescription className="ml-auto">
                  <ActivityIcon className="w-4 h-4 mr-1" />
                  Live
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4 text-sm p-6">
                <div className="flex items-center">
                  <div>Malware Detected</div>
                  <div className="font-semibold ml-auto">12</div>
                </div>
                <div className="flex items-center">
                  <div>Phishing Attempts</div>
                  <div className="font-semibold ml-auto">8</div>
                </div>
                <div className="flex items-center">
                  <div>DDoS Attacks</div>
                  <div className="font-semibold ml-auto">4</div>
                </div>
                <div className="flex items-center">
                  <div>Unauthorized Access</div>
                  <div className="font-semibold ml-auto">2</div>
                </div>
              </CardContent>
            </Card>
          </div>
          <Card className="relative overflow-hidden">
            <CardHeader className="flex flex-row items-center border-b">
              <CardTitle>Threat Detection</CardTitle>
              <CardDescription className="ml-auto">
                <ActivityIcon className="w-4 h-4 mr-1" />
                Live
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Threat Type</TableHead>
                    <TableHead>Source IP</TableHead>
                    <TableHead>Destination IP</TableHead>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Severity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell>Malware</TableCell>
                    <TableCell>192.168.1.100</TableCell>
                    <TableCell>10.0.0.5</TableCell>
                    <TableCell>2023-06-24 12:34:56</TableCell>
                    <TableCell className="text-red-500 font-semibold">High</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>DDoS Attack</TableCell>
                    <TableCell>172.16.0.50</TableCell>
                    <TableCell>192.168.2.25</TableCell>
                    <TableCell>2023-06-24 11:22:33</TableCell>
                    <TableCell className="text-orange-500 font-semibold">Medium</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>Phishing Attempt</TableCell>
                    <TableCell>10.0.0.12</TableCell>
                    <TableCell>192.168.1.100</TableCell>
                    <TableCell>2023-06-23 23:45:67</TableCell>
                    <TableCell className="text-yellow-500 font-semibold">Low</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>Unauthorized Access</TableCell>
                    <TableCell>192.168.2.25</TableCell>
                    <TableCell>10.0.0.5</TableCell>
                    <TableCell>2023-06-23 18:09:12</TableCell>
                    <TableCell className="text-red-500 font-semibold">High</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}

function ActivityIcon(props :  any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />
    </svg>
  )
}


function LineChart(props :  any) {
  return (
    <div {...props}>
      <ResponsiveLine
        data={[
          {
            id: "Desktop",
            data: [
              { x: "Jan", y: 43 },
              { x: "Feb", y: 137 },
              { x: "Mar", y: 61 },
              { x: "Apr", y: 145 },
              { x: "May", y: 26 },
              { x: "Jun", y: 154 },
            ],
          },
          {
            id: "Mobile",
            data: [
              { x: "Jan", y: 60 },
              { x: "Feb", y: 48 },
              { x: "Mar", y: 177 },
              { x: "Apr", y: 78 },
              { x: "May", y: 96 },
              { x: "Jun", y: 204 },
            ],
          },
        ]}
        margin={{ top: 10, right: 10, bottom: 40, left: 40 }}
        xScale={{
          type: "point",
        }}
        yScale={{
          type: "linear",
        }}
        axisTop={null}
        axisRight={null}
        axisBottom={{
          tickSize: 0,
          tickPadding: 16,
        }}
        axisLeft={{
          tickSize: 0,
          tickValues: 5,
          tickPadding: 16,
        }}
        colors={["#2563eb", "#e11d48"]}
        pointSize={6}
        useMesh={true}
        gridYValues={6}
        theme={{
          tooltip: {
            chip: {
              borderRadius: "9999px",
            },
            container: {
              fontSize: "12px",
              textTransform: "capitalize",
              borderRadius: "6px",
            },
          },
          grid: {
            line: {
              stroke: "#f3f4f6",
            },
          },
        }}
        role="application"
      />
    </div>
  )
}


function PieChart(props :  any) {
  return (
    <div {...props}>
      <ResponsivePie
        data={[
          { id: "Jan", value: 111 },
          { id: "Feb", value: 157 },
          { id: "Mar", value: 129 },
          { id: "Apr", value: 150 },
          { id: "May", value: 119 },
          { id: "Jun", value: 72 },
        ]}
        sortByValue
        margin={{ top: 10, right: 10, bottom: 10, left: 10 }}
        cornerRadius={0}
        padAngle={0}
        borderWidth={1}
        borderColor={"#ffffff"}
        enableArcLinkLabels={false}
        arcLabel={(d) => `${d.id}`}
        arcLabelsTextColor={"#ffffff"}
        arcLabelsRadiusOffset={0.65}
        colors={["#2563eb"]}
        theme={{
          labels: {
            text: {
              fontSize: "18px",
            },
          },
          tooltip: {
            chip: {
              borderRadius: "9999px",
            },
            container: {
              fontSize: "12px",
              textTransform: "capitalize",
              borderRadius: "6px",
            },
          },
        }}
        role="application"
      />
    </div>
  )
}


function ShieldIcon(props :  any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
    </svg>
  )
}


function StackedbarChart(props :  any) {
  return (
    <div {...props}>
      <ResponsiveBar
        data={[
          { name: "Jan", desktop: 111, mobile: 99 },
          { name: "Feb", desktop: 157, mobile: 87 },
          { name: "Mar", desktop: 129, mobile: 89 },
          { name: "Apr", desktop: 187, mobile: 151 },
          { name: "May", desktop: 119, mobile: 127 },
          { name: "Jun", desktop: 20, mobile: 121 },
        ]}
        keys={["desktop", "mobile"]}
        indexBy="name"
        margin={{ top: 0, right: 0, bottom: 40, left: 40 }}
        padding={0.3}
        colors={["#2563eb", "#e11d48"]}
        axisBottom={{
          tickSize: 0,
          tickPadding: 16,
        }}
        axisLeft={{
          tickSize: 0,
          tickValues: 4,
          tickPadding: 16,
        }}
        gridYValues={4}
        theme={{
          tooltip: {
            chip: {
              borderRadius: "9999px",
            },
            container: {
              fontSize: "12px",
              textTransform: "capitalize",
              borderRadius: "6px",
            },
          },
          grid: {
            line: {
              stroke: "#f3f4f6",
            },
          },
        }}
        tooltipLabel={({ id }) => `${id}`}
        enableLabel={false}
        role="application"
        ariaLabel="A stacked bar chart"
      />
    </div>
  )
}
