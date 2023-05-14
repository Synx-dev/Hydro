--Testing Area, Use for fixing bugs or updating script without deleted source

--[[
-- = focat's notification lib = --
  _____      .__   
_/ ____\____ |  |  
\   __\/    \|  |  
 |  | |   |  \  |__
 |__| |___|  /____/
           \/      
-- = focat's notification lib = --

#noskidsallowed
https://github.com/Code1Tech/utils/

[ How To Use - Snippet ]
local fnl = loadstring(game:HttpGetAsync 'https://raw.githubusercontent.com/Code1Tech/utils/main/notification.lua')()

fnl:MakeNotification({
	Title = "Your Title Here",
	Text = "Your Text Here",
	Duration = 5 -- Your Duration (in seconds)
})
[ ez ]

]]--
protect = (syn.protect_gui or gethui) --// Protect GUI/Instance Function \\--

local lib = {}

local Converted = {
	["_focat's notification lib"] = Instance.new("ScreenGui");
	["_Notifications"] = Instance.new("Frame");
	["_Template"] = Instance.new("Frame");
	["_UICorner"] = Instance.new("UICorner");
	["_Title"] = Instance.new("TextLabel");
	["_Description"] = Instance.new("TextLabel");
	["_Icon"] = Instance.new("ImageButton");
	["_UIStroke"] = Instance.new("UIStroke");
	["_UIListLayout"] = Instance.new("UIListLayout");
}

-- Properties:

Converted["_focat's notification lib"].DisplayOrder = 999999999
Converted["_focat's notification lib"].ResetOnSpawn = false
Converted["_focat's notification lib"].ZIndexBehavior = Enum.ZIndexBehavior.Sibling
Converted["_focat's notification lib"].Name = "focat's notification lib"
--protect(Converted["_focat's notification lib"]) :( bypassed
Converted["_focat's notification lib"].Parent = game:GetService("CoreGui")

Converted["_Notifications"].AnchorPoint = Vector2.new(1, 1)
Converted["_Notifications"].BackgroundColor3 = Color3.fromRGB(255, 255, 255)
Converted["_Notifications"].BackgroundTransparency = 1
Converted["_Notifications"].BorderSizePixel = 0
Converted["_Notifications"].ClipsDescendants = true
Converted["_Notifications"].Position = UDim2.new(1, -25, 1, -25)
Converted["_Notifications"].Size = UDim2.new(0, 296, 0, 578)
Converted["_Notifications"].Name = "Notifications"
Converted["_Notifications"].Parent = Converted["_focat's notification lib"]

Converted["_Template"].AnchorPoint = Vector2.new(0.5, 0.5)
Converted["_Template"].BackgroundColor3 = Color3.fromRGB(43.00000123679638, 43.00000123679638, 43.00000123679638)
Converted["_Template"].BackgroundTransparency = 0.20000000298023224
Converted["_Template"].BorderSizePixel = 0
Converted["_Template"].Position = UDim2.new(0.5, 0, 0.915000021, 0)
Converted["_Template"].Size = UDim2.new(0, 295, 0, 91)
Converted["_Template"].Visible = false
Converted["_Template"].ZIndex = 100
Converted["_Template"].Name = "Template"
Converted["_Template"].Parent = Converted["_Notifications"]

Converted["_UICorner"].Parent = Converted["_Template"]

Converted["_Title"].Font = Enum.Font.GothamBold
Converted["_Title"].Text = "fnl"
Converted["_Title"].TextColor3 = Color3.fromRGB(240.00000089406967, 240.00000089406967, 240.00000089406967)
Converted["_Title"].TextScaled = true
Converted["_Title"].TextSize = 14
Converted["_Title"].TextWrapped = true
Converted["_Title"].TextXAlignment = Enum.TextXAlignment.Left
Converted["_Title"].AnchorPoint = Vector2.new(0.5, 0.5)
Converted["_Title"].BackgroundColor3 = Color3.fromRGB(255, 255, 255)
Converted["_Title"].BackgroundTransparency = 1
Converted["_Title"].BorderSizePixel = 0
Converted["_Title"].Position = UDim2.new(0.543378413, 0, 0.233989015, 0)
Converted["_Title"].Size = UDim2.new(0, 233, 0, 15)
Converted["_Title"].ZIndex = 105
Converted["_Title"].Name = "Title"
Converted["_Title"].Parent = Converted["_Template"]

Converted["_Description"].Font = Enum.Font.GothamMedium
Converted["_Description"].Text = "so kewl"
Converted["_Description"].TextColor3 = Color3.fromRGB(240.00000089406967, 240.00000089406967, 240.00000089406967)
Converted["_Description"].TextSize = 14
Converted["_Description"].TextTransparency = 0.30000001192092896
Converted["_Description"].TextWrapped = true
Converted["_Description"].TextXAlignment = Enum.TextXAlignment.Left
Converted["_Description"].TextYAlignment = Enum.TextYAlignment.Top
Converted["_Description"].AnchorPoint = Vector2.new(0.5, 0.5)
Converted["_Description"].BackgroundColor3 = Color3.fromRGB(255, 255, 255)
Converted["_Description"].BackgroundTransparency = 1
Converted["_Description"].BorderSizePixel = 0
Converted["_Description"].Position = UDim2.new(0.508141577, 0, 0.637223482, 0)
Converted["_Description"].Size = UDim2.new(0, 269, 0, 43)
Converted["_Description"].ZIndex = 105
Converted["_Description"].Name = "Description"
Converted["_Description"].Parent = Converted["_Template"]

Converted["_Icon"].Image = "rbxassetid://7072706001"
Converted["_Icon"].ImageColor3 = Color3.fromRGB(204.0000182390213, 204.0000182390213, 204.0000182390213)
Converted["_Icon"].AnchorPoint = Vector2.new(0.5, 0.5)
Converted["_Icon"].BackgroundTransparency = 1
Converted["_Icon"].BorderSizePixel = 0
Converted["_Icon"].LayoutOrder = 5
Converted["_Icon"].Position = UDim2.new(0.0912162289, 0, 0.233880579, 0)
Converted["_Icon"].Size = UDim2.new(0, 20, 0, 20)
Converted["_Icon"].ZIndex = 105
Converted["_Icon"].Name = "Icon"
Converted["_Icon"].Parent = Converted["_Template"]

Converted["_UIStroke"].Color = Color3.fromRGB(93.00000205636024, 93.00000205636024, 93.00000205636024)
Converted["_UIStroke"].Thickness = 1.2000000476837158
Converted["_UIStroke"].Parent = Converted["_Template"]

Converted["_UIListLayout"].Padding = UDim.new(0, 6)
Converted["_UIListLayout"].HorizontalAlignment = Enum.HorizontalAlignment.Right
Converted["_UIListLayout"].SortOrder = Enum.SortOrder.LayoutOrder
Converted["_UIListLayout"].VerticalAlignment = Enum.VerticalAlignment.Bottom
Converted["_UIListLayout"].Parent = Converted["_Notifications"]

baseNotif = Converted["_Template"]

function tween(go, t, dir)
    dir = dir or "in"
    local obj = go

    local startTransparency = (dir == "in") and 1 or 0
    local endTransparency = (dir == "in") and 0 or 1

    obj.BackgroundTransparency = startTransparency

    local tweenInfo = TweenInfo.new(t, Enum.EasingStyle.Quint, Enum.EasingDirection.Out, 0, false, 0)

    local tween = game:GetService("TweenService"):Create(obj, tweenInfo, {
        BackgroundTransparency = endTransparency
    })
    tween:Play()

    if dir == "out" then
        for _, e in pairs(obj:GetDescendants()) do
            if e:IsA("GuiObject") then
                if e:IsA("TextLabel") then
                    local texttween = game:GetService("TweenService"):Create(e, tweenInfo, {
                        TextTransparency = endTransparency
                    })
                    texttween:Play()
                elseif e:IsA("ImageLabel") or e:IsA("ImageButton") then
                    local imgt = game:GetService("TweenService"):Create(e, tweenInfo, {
                        ImageTransparency = endTransparency
                    })
                    imgt:Play()
                elseif e:IsA("UIStroke") then
                    local st = game:GetService("TweenService"):Create(e, tweenInfo, {
                        Transparency = endTransparency
                    })
                    st:Play()
                end
            end
        end
    end
end

function lib:MakeNotification(notif_table:table)
	local nt = notif_table or {
		Title = "focat's notification lib",
		Text = "This is a test notification.",
        Icon = "",
		Duration = 5
	}

	local title = nt.Title
	local text = nt.Text
    local icon = nt.Icon
	local dur = nt.Duration

	local newNotif = baseNotif:Clone()
	newNotif.Parent = Converted["_Notifications"]
	newNotif.Title.Text = title
	newNotif.Description.Text = text
    newNotf.Icon.Image = icon
	newNotif.Visible = true
	newNotif.Name = "CiriusNotification"

	local holder = Converted["_Notifications"]
	local notifications = holder:GetChildren()
	local numNotifications = #notifications

	local layout = Converted["_UIListLayout"]
	local layoutOrder = layout.Padding.Offset

	for i, notification in ipairs(notifications) do
		if notification ~= baseNotif and
			notification ~= newNotif and
			notification ~= layout
		then
			if numNotifications == 1 then
				layoutOrder = layoutOrder - 1
			else
				layoutOrder = notification.LayoutOrder + 1
			end
			tween(notification, 0.25)
		end
	end

	newNotif.LayoutOrder = layoutOrder

	tween(newNotif, 0.25, "in")

	spawn(function()
		wait(dur)
		tween(newNotif, 0.25, "out")
		wait(0.25)
		newNotif:Destroy()
	end)
end

return lib
