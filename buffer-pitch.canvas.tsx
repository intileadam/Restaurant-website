import { useState } from "react";
import {
  Stack,
  Row,
  Grid,
  H1,
  H2,
  H3,
  Text,
  Card,
  CardHeader,
  CardBody,
  Callout,
  Pill,
  Divider,
  Stat,
  useHostTheme,
} from "cursor/canvas";

type Slide =
  | "problem"
  | "solution"
  | "why_not_build"
  | "yelp_nextdoor"
  | "how_it_works"
  | "cost"
  | "next_steps";

const SLIDES: { id: Slide; label: string }[] = [
  { id: "problem", label: "The Problem" },
  { id: "solution", label: "The Solution" },
  { id: "why_not_build", label: "Why Not Build It?" },
  { id: "yelp_nextdoor", label: "Yelp + Nextdoor" },
  { id: "how_it_works", label: "How It Works" },
  { id: "cost", label: "What It Costs" },
  { id: "next_steps", label: "Next Steps" },
];

function SlideNav({
  current,
  onSelect,
}: {
  current: Slide;
  onSelect: (s: Slide) => void;
}) {
  return (
    <Row gap={6} wrap>
      {SLIDES.map((s) => (
        <span key={s.id}>
          <Pill
            active={current === s.id}
            onClick={() => onSelect(s.id)}
          >
            {s.label}
          </Pill>
        </span>
      ))}
    </Row>
  );
}

function ProblemSlide() {
  const theme = useHostTheme();
  return (
    <Stack gap={24}>
      <H1>The Problem</H1>
      <Text
        style={{ fontSize: 18, lineHeight: "1.6" }}
      >
        Right now, every time you want to post something, you have to sign into
        each platform separately — Facebook, Instagram, TikTok, Google, Yelp,
        Nextdoor. That's 6 different logins, 6 different interfaces, and a lot
        of wasted time.
      </Text>

      <H2>What that looks like today</H2>
      <Stack gap={2}>
        {[
          "Take a photo of tonight's special",
          "Open Facebook, write a caption, post it",
          "Open Instagram, resize the photo, write a caption, post it",
          "Open TikTok, maybe make a short video, post it",
          "Open Google Business, write an update, post it",
          "Open Yelp, write an update, post it",
          "Open Nextdoor, write a neighborhood post",
        ].map((step, i) => (
          <div
            key={i}
            style={{
              padding: "10px 14px",
              background: i === 0 ? theme.fill.secondary : "transparent",
              borderRadius: 6,
            }}
          >
            <Row gap={12} align="center">
              <Text
                weight="bold"
                style={{
                  color: theme.accent.primary,
                  minWidth: 24,
                  textAlign: "right",
                }}
              >
                {i + 1}.
              </Text>
              <Text style={{ fontSize: 16 }}>{step}</Text>
            </Row>
          </div>
        ))}
      </Stack>

      <div
        style={{
          background: theme.fill.tertiary,
          borderRadius: 8,
          padding: "16px 20px",
          textAlign: "center",
        }}
      >
        <Text style={{ fontSize: 20 }} weight="semibold">
          That's 30-45 minutes for a single post.
        </Text>
        <Text tone="secondary" style={{ marginTop: 4 }}>
          Multiply that by 3-5 posts per week and it's hours of your time.
        </Text>
      </div>
    </Stack>
  );
}

function SolutionSlide() {
  const theme = useHostTheme();
  return (
    <Stack gap={24}>
      <H1>The Solution: Buffer</H1>
      <Text style={{ fontSize: 18, lineHeight: "1.6" }}>
        Buffer is a tool that lets you write one post and send it to Facebook,
        Instagram, TikTok, and Google all at once. You sign in once, and
        everything goes out from one screen.
      </Text>

      <H2>What it looks like with Buffer</H2>
      <Stack gap={2}>
        {[
          "Take a photo of tonight's special",
          "Open Buffer, write your caption once",
          "Check the boxes for Facebook, Instagram, TikTok, and Google",
          'Hit "Schedule" — done',
        ].map((step, i) => (
          <div
            key={i}
            style={{
              padding: "10px 14px",
              background: i === 3 ? theme.fill.secondary : "transparent",
              borderRadius: 6,
            }}
          >
            <Row gap={12} align="center">
              <Text
                weight="bold"
                style={{
                  color: theme.accent.primary,
                  minWidth: 24,
                  textAlign: "right",
                }}
              >
                {i + 1}.
              </Text>
              <Text style={{ fontSize: 16 }}>{step}</Text>
            </Row>
          </div>
        ))}
      </Stack>

      <div
        style={{
          background: theme.fill.tertiary,
          borderRadius: 8,
          padding: "16px 20px",
          textAlign: "center",
        }}
      >
        <Text style={{ fontSize: 20 }} weight="semibold">
          5 minutes instead of 45.
        </Text>
        <Text tone="secondary" style={{ marginTop: 4 }}>
          You can even schedule a whole week of posts in one 20-minute sitting.
        </Text>
      </div>

      <Grid columns={3} gap={16}>
        <Stat value="4" label="Platforms at once" />
        <Stat value="5 min" label="Per post" />
        <Stat value="Free" label="To start" tone="success" />
      </Grid>
    </Stack>
  );
}

function WhyNotBuildSlide() {
  const theme = useHostTheme();

  const rows = [
    {
      label: "Time to get started",
      buffer: "30 minutes",
      custom: "2-3 months of development",
    },
    {
      label: "Cost",
      buffer: "Free, or $6/channel/month",
      custom: "Developer fees + hosting + ongoing fixes",
    },
    {
      label: "When Facebook changes something",
      buffer: "Buffer handles it automatically",
      custom: "We have to find and fix the problem ourselves",
    },
    {
      label: "Mobile app",
      buffer: "Included — post from your phone",
      custom: "Would need to be built separately",
    },
    {
      label: "If something breaks",
      buffer: "Buffer's support team fixes it",
      custom: "We fix it, on our own time",
    },
    {
      label: "AI help writing captions",
      buffer: "Built in",
      custom: "Would need to be built separately",
    },
  ];

  return (
    <Stack gap={24}>
      <H1>Why Not Build Our Own?</H1>
      <Text style={{ fontSize: 18, lineHeight: "1.6" }}>
        It's a fair question. But building a tool like this ourselves would be
        like building your own oven instead of buying one. Here's the
        comparison:
      </Text>

      <Stack gap={1}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr 1fr",
            gap: 1,
            background: theme.stroke.tertiary,
            borderRadius: 8,
            overflow: "hidden",
          }}
        >
          <div style={{ background: theme.bg.editor, padding: "12px 16px" }}>
            <Text weight="semibold" tone="secondary" size="small">
              Question
            </Text>
          </div>
          <div style={{ background: theme.bg.editor, padding: "12px 16px" }}>
            <Text
              weight="semibold"
              size="small"
              style={{ color: theme.accent.primary }}
            >
              Using Buffer
            </Text>
          </div>
          <div style={{ background: theme.bg.editor, padding: "12px 16px" }}>
            <Text weight="semibold" size="small" tone="secondary">
              Building Custom
            </Text>
          </div>
          {rows.map((row, i) => (
            <>
              <div
                key={`l${i}`}
                style={{
                  background: theme.bg.editor,
                  padding: "10px 16px",
                }}
              >
                <Text weight="medium" size="small">
                  {row.label}
                </Text>
              </div>
              <div
                key={`b${i}`}
                style={{
                  background: theme.bg.editor,
                  padding: "10px 16px",
                }}
              >
                <Text size="small" style={{ color: theme.category.green }}>
                  {row.buffer}
                </Text>
              </div>
              <div
                key={`c${i}`}
                style={{
                  background: theme.bg.editor,
                  padding: "10px 16px",
                }}
              >
                <Text size="small" tone="tertiary">
                  {row.custom}
                </Text>
              </div>
            </>
          ))}
        </div>
      </Stack>

      <Callout tone="info" title="Bottom line">
        Buffer is used by thousands of restaurants already. Building our own
        version would cost more, take months, and need constant upkeep — all to
        do what Buffer already does for free.
      </Callout>
    </Stack>
  );
}

function YelpNextdoorSlide() {
  const theme = useHostTheme();
  return (
    <Stack gap={24}>
      <H1>What About Yelp and Nextdoor?</H1>
      <Text style={{ fontSize: 18, lineHeight: "1.6" }}>
        Great question. These two platforms work differently from the others, and
        no tool — not even a custom-built one — can fully manage them. Here's
        why:
      </Text>

      <Card>
        <CardHeader trailing={<Pill>Separate login needed</Pill>}>
          Yelp
        </CardHeader>
        <CardBody>
          <Stack gap={8}>
            <Text>
              Yelp doesn't allow any outside tool to post on your behalf. It's
              locked down. Even if we built something from scratch, we still
              couldn't post to Yelp through it.
            </Text>
            <Text weight="semibold">What to do instead:</Text>
            <Text>
              Use Yelp Connect — it's Yelp's own posting tool. You log into your
              Yelp business page and post updates there. Your posts show up in
              local diners' Yelp feeds and in email digests that reach millions
              of users. This is actually better than a third-party tool because
              Yelp promotes these posts directly to nearby customers.
            </Text>
          </Stack>
        </CardBody>
      </Card>

      <Card>
        <CardHeader trailing={<Pill>Separate login needed</Pill>}>
          Nextdoor
        </CardHeader>
        <CardBody>
          <Stack gap={8}>
            <Text>
              Nextdoor has very limited support for outside tools. Almost no
              social media manager can post to Nextdoor directly.
            </Text>
            <Text weight="semibold">What to do instead:</Text>
            <Text>
              Post to Nextdoor manually. Nextdoor posts are usually
              neighborhood-focused updates (events, specials for locals) and
              don't need to go out as frequently. Once a week or less is typical.
            </Text>
          </Stack>
        </CardBody>
      </Card>

      <Divider />

      <H2>The New Routine</H2>
      <div
        style={{
          background: theme.fill.tertiary,
          borderRadius: 8,
          padding: 20,
        }}
      >
        <Stack gap={12}>
          <Row gap={12} align="center">
            <div
              style={{
                background: theme.accent.primary,
                color: theme.text.onAccent,
                borderRadius: 20,
                width: 28,
                height: 28,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 700,
                fontSize: 14,
                flexShrink: 0,
              }}
            >
              1
            </div>
            <Stack gap={2}>
              <Text weight="semibold">Buffer</Text>
              <Text tone="secondary" size="small">
                Facebook + Instagram + TikTok + Google — all at once
              </Text>
            </Stack>
          </Row>
          <Row gap={12} align="center">
            <div
              style={{
                background: theme.accent.primary,
                color: theme.text.onAccent,
                borderRadius: 20,
                width: 28,
                height: 28,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 700,
                fontSize: 14,
                flexShrink: 0,
              }}
            >
              2
            </div>
            <Stack gap={2}>
              <Text weight="semibold">Yelp Connect</Text>
              <Text tone="secondary" size="small">
                Quick update on your Yelp page when you have news
              </Text>
            </Stack>
          </Row>
          <Row gap={12} align="center">
            <div
              style={{
                background: theme.accent.primary,
                color: theme.text.onAccent,
                borderRadius: 20,
                width: 28,
                height: 28,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 700,
                fontSize: 14,
                flexShrink: 0,
              }}
            >
              3
            </div>
            <Stack gap={2}>
              <Text weight="semibold">Nextdoor</Text>
              <Text tone="secondary" size="small">
                Occasional neighborhood post — once a week or less
              </Text>
            </Stack>
          </Row>
        </Stack>
      </div>

      <Callout tone="success" title="3 logins instead of 7">
        And the first one (Buffer) handles 80% of the work. The daily posting
        is consolidated into one place.
      </Callout>
    </Stack>
  );
}

function HowItWorksSlide() {
  const theme = useHostTheme();

  const steps = [
    {
      title: "Sign up at buffer.com",
      detail: "Free account, no credit card. Takes 2 minutes.",
    },
    {
      title: "Connect your accounts",
      detail:
        "Link your Facebook Page, Instagram Business, TikTok, and Google Business Profile. Buffer walks you through it — about 5 minutes.",
    },
    {
      title: "Set your posting schedule",
      detail:
        'Pick the days and times you want posts to go out. Example: Monday, Wednesday, Friday at 11:30 AM (right before lunch).',
    },
    {
      title: "Create a post",
      detail:
        "Take a photo, write a caption (or let AI help you write one), pick which platforms, and add it to your queue.",
    },
    {
      title: "Posts go out automatically",
      detail:
        "Buffer publishes at your scheduled times. You don't have to be online.",
    },
    {
      title: "Batch your week",
      detail:
        "Once you get comfortable, sit down on Sunday for 20 minutes and schedule the whole week. Then don't think about social media until next Sunday.",
    },
  ];

  return (
    <Stack gap={24}>
      <H1>How It Actually Works</H1>
      <Text style={{ fontSize: 18, lineHeight: "1.6" }}>
        Here's exactly what the setup and daily routine looks like. No tech
        background needed.
      </Text>

      <Stack gap={4}>
        {steps.map((step, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              gap: 16,
              padding: "14px 16px",
              borderRadius: 8,
              background: i === 5 ? theme.fill.secondary : "transparent",
            }}
          >
            <div
              style={{
                background:
                  i === 5 ? theme.accent.primary : theme.fill.primary,
                color:
                  i === 5 ? theme.text.onAccent : theme.text.primary,
                borderRadius: 20,
                width: 32,
                height: 32,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 700,
                fontSize: 15,
                flexShrink: 0,
                marginTop: 2,
              }}
            >
              {i + 1}
            </div>
            <Stack gap={2}>
              <Text weight="semibold" style={{ fontSize: 16 }}>
                {step.title}
              </Text>
              <Text tone="secondary">{step.detail}</Text>
            </Stack>
          </div>
        ))}
      </Stack>

      <Callout tone="info" title="Phone app included">
        Buffer has a free mobile app. You can snap a photo in the kitchen, write
        a quick caption on your phone, and add it to the queue in under 2
        minutes. It goes out at the next scheduled time automatically.
      </Callout>
    </Stack>
  );
}

function CostSlide() {
  const theme = useHostTheme();
  return (
    <Stack gap={24}>
      <H1>What It Costs</H1>

      <Grid columns={2} gap={16}>
        <Card>
          <CardHeader trailing={<Pill active>Recommended to start</Pill>}>
            Free Plan
          </CardHeader>
          <CardBody>
            <Stack gap={12}>
              <Text
                weight="bold"
                style={{ fontSize: 28, color: theme.category.green }}
              >
                $0/month
              </Text>
              <Stack gap={6}>
                <Text>3 social media channels</Text>
                <Text>10 scheduled posts per channel</Text>
                <Text>AI caption help included</Text>
                <Text>Mobile app included</Text>
              </Stack>
              <Divider />
              <Text tone="secondary" size="small">
                Perfect for getting started. Covers Facebook + Instagram + one
                more (like TikTok or Google Business).
              </Text>
            </Stack>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>Essentials Plan</CardHeader>
          <CardBody>
            <Stack gap={12}>
              <Text weight="bold" style={{ fontSize: 28 }}>
                $5-6/channel/month
              </Text>
              <Stack gap={6}>
                <Text>Unlimited scheduled posts</Text>
                <Text>More AI credits for captions</Text>
                <Text>Better analytics and reporting</Text>
                <Text>Engagement tools</Text>
              </Stack>
              <Divider />
              <Text tone="secondary" size="small">
                If you connect 4 channels (Facebook, Instagram, TikTok, Google),
                that's about $20-24/month. Upgrade when the free plan feels
                limiting.
              </Text>
            </Stack>
          </CardBody>
        </Card>
      </Grid>

      <H2>For comparison</H2>
      <div
        style={{
          background: theme.fill.tertiary,
          borderRadius: 8,
          padding: 20,
        }}
      >
        <Grid columns={3} gap={16}>
          <Stack gap={4} style={{ textAlign: "center" }}>
            <Text
              weight="bold"
              style={{ fontSize: 24, color: theme.category.green }}
            >
              $0-24/mo
            </Text>
            <Text size="small" tone="secondary">
              Buffer
            </Text>
          </Stack>
          <Stack gap={4} style={{ textAlign: "center" }}>
            <Text weight="bold" style={{ fontSize: 24 }}>
              $500-3,000/mo
            </Text>
            <Text size="small" tone="secondary">
              Hiring a social media manager
            </Text>
          </Stack>
          <Stack gap={4} style={{ textAlign: "center" }}>
            <Text weight="bold" style={{ fontSize: 24 }}>
              $5,000+
            </Text>
            <Text size="small" tone="secondary">
              Building a custom tool
            </Text>
          </Stack>
        </Grid>
      </div>
    </Stack>
  );
}

function NextStepsSlide() {
  const theme = useHostTheme();
  return (
    <Stack gap={24}>
      <H1>Next Steps</H1>
      <Text style={{ fontSize: 18, lineHeight: "1.6" }}>
        We can get this up and running today. Here's the plan:
      </Text>

      <Stack gap={4}>
        {[
          {
            title: "Today: Create a free Buffer account",
            detail:
              "Go to buffer.com, sign up, and connect Facebook, Instagram, and one more channel. 30 minutes.",
          },
          {
            title: "Today: Schedule your first 3 posts",
            detail:
              "Use photos you already have. Try the AI assistant for caption ideas. Get a feel for the tool.",
          },
          {
            title: "This week: Set up Yelp Connect",
            detail:
              "Log into your Yelp business page and start posting updates there. Aim for one post per week.",
          },
          {
            title: "This week: Add TikTok and Google Business to Buffer",
            detail:
              "If you didn't connect them on day one, add them now. Still free on the 3-channel plan (pick your top 3).",
          },
          {
            title: "Week 2: Evaluate",
            detail:
              "Are you saving time? Do you want to add more channels? If yes, the paid plan is $5-6 per channel.",
          },
        ].map((step, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              gap: 16,
              padding: "14px 16px",
              borderRadius: 8,
              background: i === 0 ? theme.fill.secondary : "transparent",
            }}
          >
            <div
              style={{
                background:
                  i === 0 ? theme.accent.primary : theme.fill.primary,
                color:
                  i === 0 ? theme.text.onAccent : theme.text.primary,
                borderRadius: 20,
                width: 32,
                height: 32,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 700,
                fontSize: 15,
                flexShrink: 0,
                marginTop: 2,
              }}
            >
              {i + 1}
            </div>
            <Stack gap={2}>
              <Text weight="semibold" style={{ fontSize: 16 }}>
                {step.title}
              </Text>
              <Text tone="secondary">{step.detail}</Text>
            </Stack>
          </div>
        ))}
      </Stack>

      <Callout tone="success" title="Zero risk">
        Buffer's free plan has no credit card requirement and no time limit.
        If it doesn't work out, you've lost nothing but 30 minutes. But
        restaurants that use scheduling tools save 5-8 hours per week on social
        media.
      </Callout>
    </Stack>
  );
}

export default function BufferPitch() {
  const [slide, setSlide] = useState<Slide>("problem");
  const theme = useHostTheme();

  const currentIndex = SLIDES.findIndex((s) => s.id === slide);
  const prevSlide = currentIndex > 0 ? SLIDES[currentIndex - 1] : null;
  const nextSlide =
    currentIndex < SLIDES.length - 1 ? SLIDES[currentIndex + 1] : null;

  return (
    <Stack gap={20} style={{ maxWidth: 800, margin: "0 auto", padding: 24 }}>
      <SlideNav current={slide} onSelect={setSlide} />
      <Divider />

      {slide === "problem" && <ProblemSlide />}
      {slide === "solution" && <SolutionSlide />}
      {slide === "why_not_build" && <WhyNotBuildSlide />}
      {slide === "yelp_nextdoor" && <YelpNextdoorSlide />}
      {slide === "how_it_works" && <HowItWorksSlide />}
      {slide === "cost" && <CostSlide />}
      {slide === "next_steps" && <NextStepsSlide />}

      <Divider />
      <Row justify="space-between">
        {prevSlide ? (
          <Pill onClick={() => setSlide(prevSlide.id)}>
            {"< "}{prevSlide.label}
          </Pill>
        ) : (
          <div />
        )}
        <Text tone="tertiary" size="small">
          {currentIndex + 1} of {SLIDES.length}
        </Text>
        {nextSlide ? (
          <Pill onClick={() => setSlide(nextSlide.id)}>
            {nextSlide.label}{" >"}
          </Pill>
        ) : (
          <div />
        )}
      </Row>
    </Stack>
  );
}
