<?php
namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class usercontroller extends Controller
{
    public function register(Request $request): \Illuminate\Http\JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string|max:255',
            'last_name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'city' => 'required|string|max:255',
            'phone' => 'required|string|max:255',
            'gender' => 'required|char|max:1',
            'date_of_birth' => 'required|date',
            'personal_image' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 400);
        }

        $ImageName = null;
        if ($request->hasFile('image')) {
            $Image = $request->file('image');
            $ImageName = time() . '_' . $Image->getClientOriginalName();
            $ImagePath = $Image->storeAs('public/images', $ImageName);
            $ImagePath = str_replace('public/', 'storage/', $ImagePath);
        }

        $user = User::create([
            'first_name' => $request->input('first_name'),
            'last_name' => $request->input('last_name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password')),
            'city' => $request->input('city'),
            'phone' => $request->input('phone'),
            'gender' => $request->input('gender'),
            'date_of_birth' => $request->input('date_of_birth'),
            'personal_image' => $ImageName,
            'verified' => false,
            'verification_code' => mt_rand(100000, 999999),
        ]);

        return response()->json(['message' => 'User registered successfully'], 201);
    }
    public function login(Request $request): \Illuminate\Http\JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        if (!Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $user = $request->user();
        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json(['token' => $token], 200);
        }

    public function index()
    {
        $users = User::all();
        return response()->json($users);
    }
    public function forgotPassword(Request $request): \Illuminate\Http\JsonResponse
    {
        // validate user input
        $validatedData = $request->validate([
            'email' => 'required|email',
        ]);

        // find the user by email
        $user = User::where('email', $validatedData['email'])->first();

        if ($user) {
            // generate a reset code for the user
            $user->reset_code = mt_rand(100000, 999999);
            $user->save();

            // send a reset code email to the user
            Mail::send('emails.reset_password', ['user' => $user], function ($message) use ($user) {
                $message->to($user->email, $user->name)
                    ->subject('Reset Your Password');
            });

            return response()->json([
                'message' => 'A reset code has been sent to your email address.',
            ]);
        } else {
            return response()->json([
                'message' => 'Invalid email address.',
            ], 422);
        }
    }

    public function resetPassword(Request $request)
    {
        // validate user input
        $validatedData = $request->validate([
            'email' => 'required|email',
            'reset_code' => 'required|min:6|max:6',
            'password' => 'required|min:8',
        ]);

        // find the user by email and reset code
        $user = User::where('email', $validatedData['email'])
            ->where('reset_code', $validatedData['reset_code'])
            ->first();

        if ($user) {
            // update the user's password
            $user->password = Hash::make($validatedData['password']);
            $user->reset_code = null;
            $user->save();
            return response()->json([
                'message' => 'Your password has been reset.',
            ]);
        } else {
            return response()->json([
                'message' => 'Invalid reset code.',
            ], 422);
        }
    }
}

